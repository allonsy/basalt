use crate::agent;
use crate::config;
use crate::keys::private::OnDiskPrivateKey;
use glob::glob;
use std::io::BufReader;
use std::os::unix::net::UnixStream;

pub struct Client {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Client {
    pub fn new() -> Result<Client, String> {
        agent::start_agent();

        let connection = UnixStream::connect(config::get_agent_socket_path());
        if connection.is_err() {
            return Err(format!(
                "Unable to connect to agent: {}",
                connection.err().unwrap()
            ));
        }

        let stream = connection.unwrap();
        let writer = stream
            .try_clone()
            .map_err(|_| "Unable to clone stream".to_string())?;
        let reader = BufReader::new(stream);

        Ok(Client { writer, reader })
    }

    fn send_message(&mut self, msg: agent::Message) -> agent::MessageResponse {
        agent::write_message(&mut self.writer, msg)
            .map_err(|_| "Unable to write to stream".to_string())?;

        agent::read_message(&mut self.reader).map_err(|_| "Unable to read from stream".to_string())
    }

    pub fn sign_message(&mut self, payload: Vec<u8>) -> Result<(String, Vec<u8>), String> {
        let resp = self.send_message(agent::Message::Sign(payload))?;

        match resp {
            agent::MessageResponsePayload::Sign(h, p) => Ok((h, p)),
            _ => Err("Mismatched response from agent".to_string()),
        }
    }
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

pub fn decrypt(keys: Vec<(String, Vec<u8>)>) -> Result<Vec<u8>, ()> {
    for (hash, payload) in keys {
        let plaintext = decrypt_key(&hash, &payload);
        if plaintext.is_ok() {
            return plaintext;
        }
    }

    Err(())
}

pub fn decrypt_key(keyhash: &str, payload: &[u8]) -> Result<Vec<u8>, ()> {
    let priv_key = get_priv_key_by_hash(keyhash)?;

    match priv_key {
        OnDiskPrivateKey::UnencryptedKey(key) => key.decrypt(payload),
        OnDiskPrivateKey::EncryptedKey(_) => {
            unimplemented!("Password decryption not yet supported")
        }
    }
}

pub fn sign_with_key(priv_key: &OnDiskPrivateKey, payload: &[u8]) -> Result<Vec<u8>, ()> {
    match priv_key {
        OnDiskPrivateKey::UnencryptedKey(key) => Ok(key.sign(payload)),
        OnDiskPrivateKey::EncryptedKey(_) => {
            unimplemented!("Password decryption not yet supported")
        }
    }
}

pub fn sign(payload: &[u8]) -> Result<(Vec<u8>, String), ()> {
    let default_key = get_default_key()?;
    let payload = sign_with_key(&default_key, payload)?;
    Ok((payload, default_key.hash()))
}

pub fn get_default_key() -> Result<OnDiskPrivateKey, ()> {
    let mut keys = get_device_keys();
    if keys.is_empty() {
        Err(())
    } else {
        Ok(keys.pop().unwrap())
    }
}

pub fn get_priv_key_by_hash(keyhash: &str) -> Result<OnDiskPrivateKey, ()> {
    let priv_keys = get_device_keys();

    for priv_key in priv_keys {
        if priv_key.hash() == keyhash {
            return Ok(priv_key);
        }
    }

    Err(())
}
