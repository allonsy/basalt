use crate::config;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use sodiumoxide::crypto::kx::SessionKey;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

#[derive(Serialize, Deserialize)]
enum Message {
    Sign,
    Decrypt,
    Quit,
    StartSession,
    EndSession,
}

struct SharedState {}

impl SharedState {
    fn new() -> Self {
        SharedState {}
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

fn start_agent() {
    let listener = UnixListener::bind(config::get_agent_socket_path());

    if (listener.is_err()) {
        return;
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

fn read_message<V>(reader: &mut BufReader<UnixStream>) -> Result<V, ()>
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

fn write_message<V>(writer: &mut UnixStream, message: V) -> Result<(), ()>
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

fn handle_message(writer: UnixStream, message: Message) {}

fn get_buffer(size: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    for _ in 0..size {
        buf.push(0);
    }
    buf
}

fn log(msg: &str) {}
