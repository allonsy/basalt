use super::Recipient;
use super::SecretStore;
use super::SecretStoreFormat;
use crate::config;
use sodiumoxide::crypto::secretbox;
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn encrypt_secret(path: &Path, payload: &str) -> Result<(), String> {
    let store_path = config::get_store_dir();
    let full_path = store_path.join(path);

    let keys = load_keys_for_file(path)?;
    let symmetric_key = secretbox::gen_key();
    let nonce = secretbox::gen_nonce();
    let enc_payload = secretbox::seal(payload.as_bytes(), &nonce, &symmetric_key);

    let recipients = keys
        .iter()
        .map(|key| Recipient {
            device_id: key.get_device_id().to_string(),
            encrypted_box: key.encrypt(&symmetric_key.0),
        })
        .collect();

    let store = SecretStore {
        nonce: nonce,
        encrypted_payload: enc_payload,
        recipients: recipients,
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

fn load_keys_for_file(path: &Path) -> Result<Vec<String>, String> {
    let store_path = config::get_store_dir().canonicalize();
    let full_path = store_path.join(path).parent();

    let mut cur_path = full_path.clone().canonicalize();
    while cur_path != store_path {
        let keys_path = cur_path.join(config::DEVICE_ID_FILE_NAME);
        if !keys_path.exists() {
            cur_path = cur_path.parent();
        } else {
            break;
        }
    }

    let file_path = cur_path.join(config::DEVICE_ID_FILE_NAME);
    let keys_file = File::open(file_path).map_err(|e| format!("Unable to read device id file: {}", e))?;
    let keys_file = keys_file.unwrap();
    let line_reader = BufReader::new(keys_file);

    let device_ids = Vec::new();
    for line in line_reader.lines() {
        if line.is_err() {
            return Err(format!("Unable to read line from device id file: {}", e));
        }
        let line = line.unwrap();
        device_ids.push(line.trim());
    }
    Ok(device_ids)
}

}
