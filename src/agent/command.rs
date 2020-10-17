use super::generate;
use super::secret;
use super::state;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize)]
pub enum Command {
    AddKey(AddKeyRequest),
    Encrypt(EncryptRequest),
    Decrypt(DecryptRequest),
}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
pub struct DecryptRequest {
    path: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptRequest {
    path: String,
    contents: Vec<u8>,
}

pub enum Response {
    AddKey,
    Decrypt(Vec<u8>),
    Encrypt,
}

pub fn processCommand(st: state::State, cmd: Command) -> Result<Response, String> {
    match cmd {
        Command::AddKey(req) => match req.keytype {
            KeyType::Sodium => {
                generate::generate_sodium_key(st, &req.name)?;
                Ok(Response::AddKey)
            }
            KeyType::PaperKey => Err("paperkey gen not yet implemented".to_string()),
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
    }
}
