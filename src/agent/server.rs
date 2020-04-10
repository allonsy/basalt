use super::pinentry;
use super::protocol;
use super::protocol::deserialize_request;
use super::protocol::deserialize_response;
use super::protocol::serialize_request;
use super::protocol::serialize_response;
use super::read_message;
use super::send_message;
use crate::config;
use crate::keys;
use crate::parse::deserialize;
use crate::util;
use nix::unistd;
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

type SharedState = Arc<Mutex<ServerState>>;

struct ServerState {
    keys: HashMap<String, Box<dyn keys::PrivateKey + Send>>,
}

pub fn start_server() -> Result<(), String> {
    let app_dir = config::get_app_dir();
    let socket_location = app_dir.join("agent.socket");
    let listener = UnixListener::bind(socket_location);
    if listener.is_err() {
        return Err(format!(
            "unable to bind to agent socket: {}",
            listener.err().unwrap(),
        ));
    }

    let fork_res = unistd::fork();
    if fork_res.is_err() {
        return Err(format!(
            "Unable to spawn server daemon: {}",
            fork_res.err().unwrap()
        ));
    }
    let fork_res = fork_res.unwrap();
    if fork_res.is_parent() {
        return Ok(());
    }
    let setsid_result = unistd::setsid();
    if setsid_result.is_err() {
        return Err(format!(
            "Unable to detach server daemon: {}",
            setsid_result.err().unwrap()
        ));
    }

    let shared_state = Arc::new(Mutex::new(ServerState {
        keys: HashMap::new(),
    }));
    let listener = listener.unwrap();
    for conn in listener.incoming() {
        match conn {
            Ok(conn) => {
                let st = shared_state.clone();
                thread::spawn(|| handle_connection(st, conn));
            }
            Err(e) => {}
        }
    }
    Ok(())
}

fn handle_connection(st: SharedState, mut conn: UnixStream) {
    let mut reader = BufReader::new(&conn);
    let message = read_message(&mut reader);
    if message.is_err() {
        let resp = protocol::Response::Failure(message.err().unwrap());
        let resp_message = serialize_response(&vec![resp]);
        send_message(&mut conn, &resp_message);
        return;
    }

    let message = message.unwrap();
    let request = deserialize_request(&message);
    if request.is_err() {
        let resp = protocol::Response::Failure(request.err().unwrap());
        let resp_message = serialize_response(&vec![resp]);
        send_message(&mut conn, &resp_message);
        return;
    }
    let request = request.unwrap();
    let resp = handle_request(st, request);
    let resp_message = serialize_response(&resp);
    send_message(&mut conn, &resp_message);
}

fn handle_request(st: SharedState, requests: Vec<protocol::Request>) -> Vec<protocol::Response> {
    let mut responses = Vec::new();
    for req in requests {
        let resp = match req {
            protocol::Request::Hello => protocol::Response::Success("HELLO".to_string()),
            protocol::Request::Clear => {
                let st = st.lock();
                if st.is_err() {
                    protocol::Response::Failure("Internal server state is poisoned".to_string())
                } else {
                    st.unwrap().keys = HashMap::new();
                    protocol::Response::Success("DONE".to_string())
                }
            }
            protocol::Request::Decrypt(decrypt_arguments) => {
                decrypt_packet(st.clone(), decrypt_arguments)
            }
            protocol::Request::Sign(sign_arguments) => sign_packet(st.clone(), sign_arguments),
            _ => protocol::Response::Failure("Unimplemented Server Request".to_string()),
        };
        responses.push(resp);
    }
    responses
}

fn decrypt_packet(st: SharedState, decrypt: protocol::DecryptRequest) -> protocol::Response {
    let locked_state = st.lock();
    if locked_state.is_err() {
        return protocol::Response::Failure(format!(
            "shared state is poisoned: {}",
            locked_state.err().unwrap()
        ));
    }
    let locked_state = locked_state.unwrap();
    let key = locked_state.keys.get(&decrypt.private_key_id);
    if key.is_none() {
        return protocol::Response::Failure(format!(
            "Unable to find key: {}",
            decrypt.private_key_id
        ));
    }
    let key = key.unwrap();
    let ciphertext = util::base32_decode(&decrypt.payload);
    if ciphertext.is_none() {
        return protocol::Response::Failure("Unable to parse base32 encoded payload".to_string());
    }
    let ciphertext = ciphertext.unwrap();
    let plaintext = key.decrypt(&ciphertext);
    if plaintext.is_err() {
        return protocol::Response::Failure("Unable to decrypt packet".to_string());
    }
    let plaintext = plaintext.unwrap();
    let encoded_plaintext = util::base32_encode(&plaintext);
    protocol::Response::Success(encoded_plaintext)
}

fn sign_packet(st: SharedState, sign: protocol::SignRequest) -> protocol::Response {
    let locked_state = st.lock();
    if locked_state.is_err() {
        return protocol::Response::Failure(format!(
            "shared state is poisoned: {}",
            locked_state.err().unwrap()
        ));
    }
    let locked_state = locked_state.unwrap();
    let key = locked_state.keys.get(&sign.private_key_id);
    if key.is_none() {
        return protocol::Response::Failure(format!("Unable to find key: {}", sign.private_key_id));
    }
    let key = key.unwrap();
    let message = util::base32_decode(&sign.payload);
    if message.is_none() {
        return protocol::Response::Failure(
            "Unable to base32 decode sign packet payload".to_string(),
        );
    }
    let message = message.unwrap();
    let signed_message = key.sign(&message);
    let encoded_signed_message = util::base32_encode(&signed_message);
    protocol::Response::Success(encoded_signed_message)
}

fn load_key(key_name: &str) -> Option<Box<dyn keys::PrivateKey + Send>> {
    let private_key_file_name = config::get_app_dir()
        .join("keys")
        .join(format!("{}.priv", key_name));
    let private_key = fs::read_to_string(private_key_file_name).ok()?;
    let private_key_json: serde_json::Value = serde_json::from_str(&private_key).ok()?;

    let parsed_key = deserialize::parse_private_key_json(&private_key_json, None);
    match parsed_key {
        Ok(key) => Some(key),
        Err(deserialize::ParseError::MissingPassword) => query_pin(key_name, &private_key_json, 3),
        _ => None,
    }
}

fn query_pin(
    key_name: &str,
    json: &serde_json::Value,
    num_retries: usize,
) -> Option<Box<dyn keys::PrivateKey + Send>> {
    for _ in 0..num_retries {
        let pin = pinentry::get_pin(key_name).ok()?;
        match deserialize::parse_private_key_json(&json, Some(&pin)) {
            Ok(key) => {
                return Some(key);
            }
            Err(deserialize::ParseError::DecryptError) => {}
            _ => {
                return None;
            }
        }
    }
    None
}