use super::Recipient;
use super::SecretStore;
use crate::config;
use crate::keys::PublicKey;
use sodiumoxide::crypto::secretbox;
use std::path::Path;

pub fn encrypt(payload: &str, keys: &Vec<Box<dyn PublicKey>>) -> SecretStore {
    let nonce = secretbox::gen_nonce();
    let symmetric_key = secretbox::gen_key();

    let enc_payload = secretbox::seal(payload.as_bytes(), &nonce, &symmetric_key);

    let mut recipients = Vec::new();
    for key in keys {
        recipients.push(Recipient {
            device_id: key.get_device_id().to_string(),
            encrypted_box: key.encrypt(&symmetric_key.0),
        });
    }

    SecretStore {
        nonce,
        encrypted_payload: enc_payload,
        recipients,
    }
}

pub fn encrypt_secret(path: &Path, payload: &str) -> Result<(), String> {
    let store_path = config::get_store_dir();
    let full_path = store_path.join(path);
}
