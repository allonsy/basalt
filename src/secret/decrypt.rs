use crate::agent::client;
use crate::agent::protocol::DecryptRequest;
use crate::config;
use crate::keys::private;
use crate::keys::public;
use crate::keys::public::KeyChain;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub fn decrypt(path: &Path) -> Result<Vec<u8>, String> {
    let store_path = config::get_store_dir();
    let full_path = store_path.join(path);
    let file_contents = fs::read_to_string(full_path)
        .map_err(|e| format!("Unable to read file for path: {}", path.as_str().unwrap()))?;

    let secret_store = serde_json::from_str(&file_contents)
        .map_err(|e| format!("Unable to parse secret store file: {}", e))?;
    let secret_store = secret_store
        .into_secret_store()
        .ok_or("Unable to decode secret store".to_string())?;
    let device_keys = private::get_device_keys();
    let keychain = KeyChain::get_keychain()?;
    let keychain_head = public::get_head();
    let trusted_keys = keychain.verify(keychain_head);

    let recipient_map = secret_store
        .recipients
        .map(|r| (r.device_id.as_str(), r.encrypted_box))
        .collect::<HashMap<&str>>();
    let mut decrypt_ids = Vec::new();

    for device_key in device_keys {
        if recipient_map.contains(device_key) {
            decrypt_ids.push(device_key.as_str());
        }
    }

    for (device_id, pkey) in trusted_keys {
        if recipient_map.contains(device_id) {
            match pkey {
                public::PublicKey::Sodium(_) => {}
            }
        }
    }

    let dec_packets = decrypt_ids
        .map(|id| -> DecryptRequest {
            DecryptRequest {
                private_key_id: id,
                payload: recipient_map.get(id).unwrap(),
            }
        })
        .collect();
    client::decrypt(dec_packets)
}
