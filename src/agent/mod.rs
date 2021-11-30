use crate::config;
use crate::keys::private::OnDiskPrivateKey;
use glob::glob;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use sodiumoxide::crypto::kx::SessionKey;
use std::collections::HashMap;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::ops::Index;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

mod handler;

#[derive(Serialize, Deserialize)]
enum Message {
    Sign(Vec<u8>),
    Decrypt,
    Quit,
    StartSession,
    EndSession,
}

#[derive(Serialize, Deserialize)]
enum MessageResponsePayload {
    Sign,
    Decrypt,
    Quit,
    StartSession,
    EndSession,
}

type MessageResponse = Result<MessageResponsePayload, String>;

struct SharedState {
    keys: HashMap<String, OnDiskPrivateKey>,
}

impl SharedState {
    fn new() -> Self {
        let device_keys = get_device_keys();

        let key_map = HashMap::new();

        for key in device_keys {
            key_map.insert(key.hash(), key);
        }
        SharedState { keys: key_map }
    }
}
struct SessionState {
    shared_state: Arc<Mutex<SharedState>>,
}

impl SessionState {
    fn new() -> Self {
        SessionState {
            shared_state: Arc::new(Mutex::new(SharedState::new())),
        }
    }
}

impl Clone for SessionState {
    fn clone(&self) -> SessionState {
        SessionState {
            shared_state: self.shared_state.clone(),
        }
    }
}

pub fn start_agent() {
    let socket_path = config::get_agent_socket_path();

    if socket_path.exists() {
        return;
    }

    let listener = UnixListener::bind(socket_path);

    if listener.is_err() {
        return;
    }

    let fork_res = fork::daemon(true, false);

    if fork_res.is_err() {
        return;
    }

    let fork_res = fork_res.unwrap();

    match fork_res {
        fork::Fork::Parent(_) => {
            return;
        }
        _ => {}
    }

    let state = SessionState::new();

    let listener = listener.unwrap();
    for stream in listener.incoming() {
        let cloned_state = state.clone();
        match stream {
            Ok(stream) => {
                thread::spawn(|| handle_stream(stream, cloned_state));
            }
            Err(_) => {}
        }
    }
}

fn handle_stream(stream: UnixStream, state: SessionState) {
    let writer = stream.try_clone();
    if writer.is_err() {
        log("Unable to clone stream");
        return;
    }

    let writer = writer.unwrap();
    let mut reader = BufReader::new(stream);

    let message: Result<Message, ()> = read_message(&mut reader);
    if message.is_err() {
        log("Unable to parsed message");
        return;
    }

    handle_message(writer, message.unwrap());
}

pub fn read_message<V>(reader: &mut BufReader<UnixStream>) -> Result<V, ()>
where
    V: DeserializeOwned,
{
    let mut msg_len_str = String::new();

    let read_res = reader.read_line(&mut &mut msg_len_str);
    if read_res.is_err() {
        log("unable to read from stream");
        return Err(());
    }

    msg_len_str = msg_len_str.trim().to_string();
    let parsed_msg_len = str::parse::<usize>(&msg_len_str);
    if parsed_msg_len.is_err() {
        log("Unable to parse message length");
        return Err(());
    }

    let mut message_bytes = get_buffer(parsed_msg_len.unwrap());
    let read_res = reader.read_exact(&mut message_bytes);

    if read_res.is_err() {
        log("Unable to read message from stream");
        return Err(());
    }
    let parsed_message = serde_json::from_slice(&message_bytes);
    if parsed_message.is_err() {
        return Err(());
    }

    Ok(parsed_message.unwrap())
}

pub fn write_message<V>(writer: &mut UnixStream, message: V) -> Result<(), ()>
where
    V: Serialize,
{
    let message_bytes = serde_json::to_vec(&message);

    if message_bytes.is_err() {
        return Err(());
    }

    let message_bytes = message_bytes.unwrap();
    let write_res = writer.write_all(&message_bytes);
    if write_res.is_err() {
        return Err(());
    }

    Ok(())
}

pub fn get_device_keys() -> Vec<OnDiskPrivateKey> {
    let mut priv_key_dir = config::get_private_key_dir();
    priv_key_dir.push("*.priv");

    let mut priv_keys = Vec::new();

    let glob_matches = glob(priv_key_dir.to_str().unwrap());
    if let Err(e) = glob_matches {
        eprintln!("Unable to read private key directory: {}", e);
        return priv_keys;
    }

    let glob_matches = glob_matches.unwrap();

    for entry in glob_matches {
        match entry {
            Ok(file_path) => {
                let parsed_priv_key = OnDiskPrivateKey::read_key(&file_path);
                match parsed_priv_key {
                    Ok(key) => priv_keys.push(key),
                    Err(e) => eprintln!("Unable to read private key: {}", e),
                };
            }
            Err(e) => eprintln!("Unable to read private key: {}", e),
        }
    }

    priv_keys
}

fn handle_message(writer: UnixStream, message: Message) {}

fn get_buffer(size: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    for _ in 0..size {
        buf.push(0);
    }
    buf
}

fn log(msg: &str) {}
