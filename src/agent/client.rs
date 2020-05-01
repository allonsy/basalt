use super::protocol::deserialize_response;
use super::protocol::serialize_request;
use super::protocol::Decrypt;
use super::protocol::DecryptRequest;
use super::protocol::Request;
use super::protocol::Response;
use super::protocol::SignRequest;
use super::read_message;
use super::send_message;
use super::server;
use crate::config;
use crate::util;
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

pub fn sign(sign_id: &str, message: &[u8]) -> Result<Vec<u8>, String> {
    let payload = util::base32_encode(message);
    let req = SignRequest {
        private_key_id: sign_id.to_string(),
        payload: payload,
    };
    let req = Request::Sign(req);
    let response = send_requests(&vec![req])?;

    if response.is_empty() {
        return Err("No response provided for request".to_string());
    }
    let sign_resp = response[0];
    match sign_resp {
        Response::Success(sign_str) => {
            let decoded = util::base32_decode(&sign_str);
            if decoded.is_none() {
                Err("Unable to parse signature response".to_string())
            } else {
                Ok(decoded.unwrap())
            }
        }
        Response::Failure(err_msg) => Err(err_msg),
    }
}

pub fn decrypt(recipients: Vec<DecryptRequest>) -> Result<Vec<u8>, String> {
    let req = Request::Decrypt(recipients);
    let resp = send_requests(vec![req])?;
    match resp {
        Response::Success(dec_str) => {
            let decoded = util::base32_decode(&dec_str);
            if decoded.is_none() {
                Err("Unable to parse decrypt response".to_string())
            } else {
                Ok(decoded.unwrap())
            }
        }
        Response::Failure(err_msg) => Err(err_msg),
    }
}
