use super::Recipient;
use super::SecretStore;
use super::SecretStoreFormat;
use crate::config;
use crate::keys::public;
use crate::keys::public::PublicKey;
use sodiumoxide::crypto::secretbox;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::Path;

pub fn encrypt_secret(path: &Path, payload: &[u8]) -> Result<(), String> {
    let store_path = config::get_store_dir();
    let full_path = store_path.join(path);

    let keys = load_keys_for_file(path)?;

    let keychain = public::KeyChain::get_keychain()?;
    let head = public::get_head();
    let trusted_keys = keychain
        .verify(head)
        .ok_or("Invalid keychain in store".to_string())?;

    let mut device_keys: HashMap<String, &PublicKey> = HashMap::new();
    for device_id in keys {
        if trusted_keys.contains_key(&device_id) {
            device_keys.insert(device_id, trusted_keys.get(&device_id).unwrap());
        }
    }

    let symmetric_key = secretbox::gen_key();
    let nonce = secretbox::gen_nonce();
    let enc_payload = secretbox::seal(payload, &nonce, &symmetric_key);

    let recipients = device_keys
        .iter()
        .map(|(id, key)| Recipient {
            device_id: id.to_string(),
            encrypted_box: key.encrypt(&symmetric_key.0),
        })
        .collect();

    let store = SecretStore {
        nonce,
        encrypted_payload: enc_payload,
        recipients,
    };

    let store_format = SecretStoreFormat::new(store);
    let json_str = serde_json::to_string(&store_format)
        .map_err(|e| format!("Unable to serialize json: {}", e))?;

    let mut secret_file =
        File::create(full_path).map_err(|e| format!("Unable to open file: {}", e))?;
    secret_file
        .write_all(json_str.as_bytes())
        .map_err(|e| format!("Unable to write to file: {}", e))
}

pub fn load_keys_for_file(path: &Path) -> Result<Vec<String>, String> {
    let store_path = config::get_store_dir();
    let full_path = store_path.join(path);

    let mut cur_path = full_path.parent().ok_or("path is invalid")?;
    while cur_path != store_path {
        let keys_path = cur_path.join(config::DEVICE_ID_FILE_NAME);
        if !keys_path.exists() {
            cur_path = cur_path.parent().ok_or("path is invalid")?;
        } else {
            break;
        }
    }

    let file_path = cur_path.join(config::DEVICE_ID_FILE_NAME);
    let keys_file =
        File::open(file_path).map_err(|e| format!("Unable to read device id file: {}", e))?;
    let line_reader = BufReader::new(keys_file);

    let mut device_ids = Vec::new();
    for line in line_reader.lines() {
        if line.is_err() {
            return Err(format!(
                "Unable to read line from device id file: {}",
                line.err().unwrap()
            ));
        }
        let line = line.unwrap();
        device_ids.push(line.trim().to_string());
    }

    Ok(device_ids)
}
