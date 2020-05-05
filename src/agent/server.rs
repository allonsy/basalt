use super::pinentry;
use super::protocol;
use super::protocol::deserialize_request;
use super::protocol::serialize_response;
use super::read_message;
use super::send_message;
use crate::config;
use crate::keys::private;
use crate::keys::private::PrivateKey;
use crate::util;
use nix::unistd;
use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::ops::DerefMut;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

const NUM_RETRIES: usize = 3;

type SharedState = Arc<Mutex<ServerState>>;

struct ServerState {
    keys: HashMap<String, PrivateKey>,
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
            Err(_) => {}
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

fn decrypt_packet(
    st: SharedState,
    decrypt_packets: Vec<protocol::DecryptRequest>,
) -> protocol::Response {
    let locked_state = st.lock();
    if locked_state.is_err() {
        return protocol::Response::Failure(format!(
            "shared state is poisoned: {}",
            locked_state.err().unwrap()
        ));
    }
    let mut locked_state = locked_state.unwrap();

    for dec_req in decrypt_packets {
        load_key(&dec_req.private_key_id, locked_state.deref_mut());
        let key = locked_state.keys.get(&dec_req.private_key_id);
        if key.is_none() {
            continue;
        }
        let key = key.unwrap();
        let ciphertext = util::base32_decode(&dec_req.payload);
        if ciphertext.is_none() {
            continue;
        }
        let ciphertext = ciphertext.unwrap();
        let plaintext = key.decrypt(&ciphertext);
        if plaintext.is_err() {
            continue;
        }
        let plaintext = plaintext.unwrap();
        let encoded_plaintext = util::base32_encode(&plaintext);
        return protocol::Response::Success(encoded_plaintext);
    }

    protocol::Response::Failure("Unable to find suitable key for decryption".to_string())
}

fn sign_packet(st: SharedState, sign: protocol::SignRequest) -> protocol::Response {
    let locked_state = st.lock();
    if locked_state.is_err() {
        return protocol::Response::Failure(format!(
            "shared state is poisoned: {}",
            locked_state.err().unwrap()
        ));
    }
    let mut locked_state = locked_state.unwrap();
    load_key(&sign.private_key_id, locked_state.deref_mut());
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
    if signed_message.is_err() {
        return protocol::Response::Failure(signed_message.err().unwrap());
    }
    let signed_message = signed_message.unwrap();
    let encoded_signed_message = util::base32_encode(&signed_message);
    protocol::Response::Success(encoded_signed_message)
}

fn load_key(key_id: &str, st: &mut ServerState) {
    if st.keys.contains_key(key_id) {
        return;
    }

    let key_file = config::get_keys_dir().join(format!("{}.sec", key_id));
    let key_bytes = fs::read_to_string(key_file);
    if key_bytes.is_err() {
        return;
    }
    let key_bytes = key_bytes.unwrap();
    let sec_key = serde_json::from_str::<private::PrivateKeyWrapper>(&key_bytes);
    if sec_key.is_err() {
        return;
    }
    let sec_key = sec_key.unwrap();
    match sec_key.key {
        private::PrivateKey::Sodium(private::SodiumPrivateKey::Unencrypted(_)) => {
            st.keys.insert(key_id.to_string(), sec_key.key);
        }
        private::PrivateKey::Sodium(private::SodiumPrivateKey::Encrypted(skey)) => {
            for _ in 0..NUM_RETRIES {
                let pin = pinentry::get_pin(key_id).ok();
                if pin.is_none() {
                    return;
                }
                let decrypted_key = skey.decrypt_key(&pin.unwrap());
                if decrypted_key.is_some() {
                    st.keys.insert(
                        key_id.to_string(),
                        private::PrivateKey::Sodium(private::SodiumPrivateKey::Unencrypted(
                            decrypted_key.unwrap(),
                        )),
                    );
                }
            }
        }
    }
}
