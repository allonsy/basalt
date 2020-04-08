use super::protocol;
use super::protocol::deserialize_request;
use super::protocol::deserialize_response;
use super::protocol::serialize_request;
use super::protocol::serialize_response;
use super::read_message;
use super::send_message;
use crate::config;
use crate::keys;
use std::collections::HashMap;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
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
    let message = read_message(&mut conn);
    if message.is_err() {
        let resp = protocol::Response::Failure(message.err().unwrap());
        let resp_message = serialize_response(&resp);
        send_message(&mut conn, &resp_message);
        return;
    }

    let message = message.unwrap();
    let request = deserialize_request(&message);
    if request.is_err() {
        let resp = protocol::Response::Failure(request.err().unwrap());
        let resp_message = serialize_response(&resp);
        send_message(&mut conn, &resp_message);
        return;
    }
    let request = request.unwrap();
    let resp = handle_request(st, request);
    let resp_message = serialize_response(&resp);
    send_message(&mut conn, &resp_message);
}

fn handle_request(st: SharedState, req: protocol::Request) -> protocol::Response {
    match req {
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
        _ => protocol::Response::Failure("Unimplemented Server Request".to_string()),
    }
}
