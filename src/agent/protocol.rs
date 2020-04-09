use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Request {
    Hello,
    Clear,
    Quit,
    Decrypt(DecryptRequest),
    Sign(SignRequest),
}

#[derive(Serialize, Deserialize)]
pub struct DecryptRequest {
    pub private_key_id: String,
    pub payload: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignRequest {
    pub private_key_id: String,
    pub payload: String,
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    Success(String),
    Failure(String),
}

pub fn serialize_request(req: &Request) -> String {
    serde_json::to_string(req).unwrap()
}

pub fn serialize_response(resp: &Response) -> String {
    serde_json::to_string(resp).unwrap()
}

pub fn deserialize_request(msg: &str) -> Result<Request, String> {
    let req = serde_json::from_str(msg);
    if req.is_err() {
        Err(format!("Unable to parse message: {}", req.err().unwrap()))
    } else {
        Ok(req.unwrap())
    }
}

pub fn deserialize_response(msg: &str) -> Result<Request, String> {
    let resp = serde_json::from_str(msg);
    if resp.is_err() {
        Err(format!("Unable to parse response: {}", resp.err().unwrap()))
    } else {
        Ok(resp.unwrap())
    }
}
