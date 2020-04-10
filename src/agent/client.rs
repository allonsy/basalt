use super::protocol::deserialize_response;
use super::protocol::serialize_request;
use super::protocol::Request;
use super::protocol::Response;
use super::read_message;
use super::send_message;
use super::server;
use crate::config;
use std::io::BufReader;
use std::os::unix::net::UnixStream;

fn get_conn() -> Result<UnixStream, String> {
    let agent_socket = config::get_app_dir().join("agent.socket");
    let first_connect = UnixStream::connect(&agent_socket);
    if first_connect.is_err() {
        server::start_server()?;
        UnixStream::connect(&agent_socket).map_err(|e| format!("Unable to connect to agent: {}", e))
    } else {
        Ok(first_connect.unwrap())
    }
}

fn send_requests(requests: &Vec<Request>) -> Result<Vec<Response>, String> {
    let mut conn = get_conn()?;
    let message = serialize_request(requests);
    send_message(&mut conn, &message)?;
    let mut reader = BufReader::new(&conn);
    let response = read_message(&mut reader)?;
    deserialize_response(&response)
}