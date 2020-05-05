use super::SecretStore;
use super::SecretStoreFormat;
use crate::agent::client;
use crate::agent::protocol::DecryptRequest;
use crate::config;
use crate::keys::private;
use crate::keys::public;
use crate::keys::public::KeyChain;
use crate::keys::public::PublicKey;
use crate::util;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub fn decrypt(path: &Path) -> Result<Vec<u8>, String> {
    let store_path = config::get_store_dir();
    let full_path = store_path.join(path);
    let file_contents = fs::read_to_string(full_path)
        .map_err(|_| format!("Unable to read file for path: {}", path.to_str().unwrap()))?;

    let secret_store: SecretStoreFormat = serde_json::from_str(&file_contents)
        .map_err(|e| format!("Unable to parse secret store file: {}", e))?;
    let secret_store = secret_store
        .into_secret_store()
        .ok_or("Unable to decode secret store".to_string())?;
    let device_keys = private::get_device_keys();
    let keychain = KeyChain::get_keychain()?;
    let keychain_head = public::get_head();
    let trusted_keys = keychain
        .verify(keychain_head)
        .ok_or("Invalid keychain in store".to_string())?;

    let local_keys = device_keys
        .into_iter()
        .map(|k| k.device_id)
        .collect::<HashSet<String>>();
    let dec_packets = build_request(&secret_store, &trusted_keys, &local_keys);
    client::decrypt(dec_packets)
}

pub fn build_request(
    secret_store: &SecretStore,
    trusted_keys: &HashMap<String, &PublicKey>,
    local_keys: &HashSet<String>,
) -> Vec<DecryptRequest> {
    let recipients = secret_store
        .recipients
        .iter()
        .map(|r| (r.device_id.to_string(), r.encrypted_box.clone()))
        .collect::<HashMap<String, Vec<u8>>>();

    let mut decrypt_ids = Vec::new();
    for key in local_keys {
        if recipients.contains_key(key) && trusted_keys.contains_key(key) {
            decrypt_ids.push(key);
        }
    }

    for (_, pkey) in trusted_keys {
        match pkey {
            PublicKey::Sodium(_) => {}
        }
    }

    decrypt_ids
        .into_iter()
        .map(|id| {
            let encoded_payload = util::base32_encode(recipients.get(id).unwrap());
            DecryptRequest {
                private_key_id: id.to_string(),
                payload: encoded_payload,
            }
        })
        .collect()
}
