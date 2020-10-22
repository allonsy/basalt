pub mod command;
pub mod generate;
pub mod keychain;
pub mod passphrase;
pub mod private;
pub mod public;
pub mod secret;
pub mod state;
pub mod vault;

use crate::config;
use fork::daemon;
use fork::Fork;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;

pub fn spawn_agent() -> Result<(), String> {
    let path = config::get_agent_socket_file();
    let listener =
        UnixListener::bind(&path).map_err(|e| format!("Unable to listen on socket: {}", e))?;
    let fork = daemon(false, false)
        .map_err(|e| format!("Unable to fork agent process from parent {}", e))?;

    match fork {
        Fork::Parent(_) => return Ok(()),
        _ => {}
    };

    let mut st = state::State::new();
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                handle_stream(&mut st, &mut stream);
            }
            Err(err) => log_message(&format!("Unable to accept incoming request: {}", err)),
        }
    }
    Ok(())
}

pub fn write_message<T>(stream: &mut UnixStream, msg: &T) -> Result<(), String>
where
    T: Serialize,
{
    let msg_bytes =
        serde_json::to_vec(msg).map_err(|e| format!("Unable to serialize json: {}", e))?;
    let msg_len = msg_bytes.len();
    let prefix = format!("{}\n", msg_len);
    stream
        .write_all(prefix.as_bytes())
        .map_err(|e| format!("Unable to write to unix socket: {}", e))?;
    stream
        .write_all(&msg_bytes)
        .map_err(|e| format!("Unable to write to unix socket: {}", e))
}

pub fn read_message(stream: &mut UnixStream) -> Result<Vec<u8>, String> {
    let mut msg_len = Vec::new();
    let mut msg_buf: [u8; 1] = [0; 1];
    loop {
        let read_len = stream
            .read(&mut msg_buf)
            .map_err(|e| format!("Unable to read from unix socket: {}", e))?;
        if read_len == 0 {
            return Err("Unix Socket is closed prematurely".to_string());
        }
        if msg_buf[0] == 10 {
            break;
        }

        msg_len.push(msg_buf[0]);
    }

    let msg_len = String::from_utf8(msg_len)
        .map_err(|e| format!("Unable to interpret message length: {}", e))?;
    let msg_len = str::parse::<usize>(&msg_len)
        .map_err(|e| format!("Unable to parse message length: {}", e))?;

    let mut num_read = 0;
    let mut msg_buf = allocate_message(msg_len);
    while num_read < msg_len {
        let n = stream
            .read(&mut msg_buf)
            .map_err(|e| format!("Unable to read message from unix socket: {}", e))?;
        if n == 0 {
            return Err("Unix Socket is closed prematurely".to_string());
        }
        num_read += n;
    }

    Ok(msg_buf)
}

pub fn parse_message<'a, T>(stream: &mut UnixStream) -> Result<T, String>
where
    T: DeserializeOwned,
{
    let msg = read_message(stream)?;
    serde_json::from_slice(&msg).map_err(|e| format!("Unable to parse message json: {}", e))
}

pub fn send_request<Request, Response>(
    stream: &mut UnixStream,
    req: Request,
) -> Result<Response, String>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    write_message(stream, &req)?;
    parse_message(stream)
}

fn send_error(msg: &str, stream: &mut UnixStream) {
    let resp: Vec<Result<command::Response, String>> = vec![Err(msg.to_string())];
    let res = write_message(stream, &resp);
    if res.is_err() {
        log_message(&res.err().unwrap());
    }
}

fn allocate_message(len: usize) -> Vec<u8> {
    let mut ret = Vec::new();
    for _ in 0..len {
        ret.push(0);
    }
    ret
}

fn handle_stream(st: &mut state::State, stream: &mut UnixStream) {
    let commands: Result<Vec<command::Command>, String> = parse_message(stream);
    if commands.is_err() {
        let err_msg = commands.err().unwrap();
        log_message(&err_msg);
        send_error(&err_msg, stream);
        return;
    }

    let commands = commands.unwrap();
    let mut responses = Vec::new();
    for command in commands {
        responses.push(command::process_command(st, command));
    }

    let write_res = write_message(stream, &responses);
    if write_res.is_err() {
        log_message(&write_res.err().unwrap());
    }
}

fn log_message(msg: &str) {
    eprintln!("{}", msg);
}
