use super::generate;
use super::secret;
use super::state;
use crate::config;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize)]
pub enum Command {
    AddKey(AddKeyRequest),
    Encrypt(EncryptRequest),
    Decrypt(DecryptRequest),
    Reload,
    Quit,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub enum KeyType {
    Sodium,
    PaperKey,
    Yubikey,
}

#[derive(Serialize, Deserialize)]
pub struct AddKeyRequest {
    name: String,
    keytype: KeyType,
}

impl AddKeyRequest {
    pub fn new(name: String, keytype: KeyType) -> Self {
        AddKeyRequest { name, keytype }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DecryptRequest {
    path: String,
}

impl DecryptRequest {
    pub fn new(path: String) -> Self {
        DecryptRequest { path }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptRequest {
    path: String,
    contents: Vec<u8>,
}

impl EncryptRequest {
    pub fn new(path: String, contents: Vec<u8>) -> Self {
        EncryptRequest { path, contents }
    }
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    AddKey(Option<String>),
    Decrypt(Vec<u8>),
    Encrypt,
    Reload,
}

pub fn process_command(st: &mut state::State, cmd: Command) -> Result<Response, String> {
    match cmd {
        Command::AddKey(req) => match req.keytype {
            KeyType::Sodium => {
                generate::generate_sodium_key(st, &req.name)?;
                Ok(Response::AddKey(None))
            }
            KeyType::PaperKey => {
                let paperkey = generate::generate_paper_key(st, &req.name)?;
                Ok(Response::AddKey(Some(paperkey)))
            }
            KeyType::Yubikey => Err("yubikey gen not yet implemented".to_string()),
        },
        Command::Encrypt(req) => {
            secret::write_secret(st, &req.path, req.contents)?;
            Ok(Response::Encrypt)
        }
        Command::Decrypt(req) => {
            let contents = secret::read_secret(st, &req.path)?;
            Ok(Response::Decrypt(contents))
        }
        Command::Reload => {
            *st = state::State::new();
            Ok(Response::Reload)
        }
        Command::Quit => {
            let _ = std::fs::remove_file(config::get_agent_socket_file());
            super::log_message("Shutting down agent");
            std::process::exit(0);
        }
    }
}
