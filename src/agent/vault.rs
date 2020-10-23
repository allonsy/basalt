use super::private;
use super::public;
use super::public::PublicKey;
use super::state;
use crate::config;
use serde::Deserialize;
use serde::Serialize;
use serde_json;
use sodiumoxide::crypto::secretbox;
use std::cmp::Ordering;
use std::fs;

#[derive(Serialize, Deserialize)]
pub struct Recipient {
    pub_key: public::PublicKeyWrapper,
    payload: Vec<u8>,
}

fn sort_recipient(rec1: &Recipient, rec2: &Recipient) -> Ordering {
    let rec1_priority = match rec1.pub_key {
        public::PublicKeyWrapper::Sodium(_) => (i32::MAX, 1, rec1.pub_key.get_key_name()),
        public::PublicKeyWrapper::Yubikey(_) => (i32::MAX, 2, rec1.pub_key.get_key_name()),
        public::PublicKeyWrapper::PaperKey(_) => (i32::MAX, 3, rec1.pub_key.get_key_name()),
    };
    let rec2_priority = match rec2.pub_key {
        public::PublicKeyWrapper::Sodium(_) => (i32::MAX, 1, rec2.pub_key.get_key_name()),
        public::PublicKeyWrapper::Yubikey(_) => (i32::MAX, 2, rec2.pub_key.get_key_name()),
        public::PublicKeyWrapper::PaperKey(_) => (i32::MAX, 3, rec2.pub_key.get_key_name()),
    };

    rec1_priority.cmp(&rec2_priority)
}

#[derive(Serialize, Deserialize)]
pub struct Vault {
    payload: Vec<u8>,
    nonce: secretbox::Nonce,
    recipients: Vec<Recipient>,
}

impl Vault {
    pub fn read_vault(path: &str) -> Result<Vault, String> {
        let path = config::get_store_directory().join(path);
        let bytes = fs::read(&path).map_err(|e| format!("filesystem error: {}", e))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("json error: {}", e))
    }

    pub fn write_vault(
        path: &str,
        message: &[u8],
        recipients: Vec<public::PublicKeyWrapper>,
    ) -> Result<(), String> {
        let sym_key = secretbox::gen_key();
        let nonce = secretbox::gen_nonce();
        let payload = secretbox::seal(message, &nonce, &sym_key);

        let recipients = recipients
            .into_iter()
            .map(|r| {
                let payload = r.encrypt(&sym_key.0);
                Recipient {
                    pub_key: r,
                    payload,
                }
            })
            .collect();
        let vault = Vault {
            payload,
            nonce,
            recipients,
        };

        let vault_json = serde_json::to_string(&vault).map_err(|e| format!("json error: {}", e))?;
        let path = config::get_store_directory().join(path);
        fs::write(path, vault_json.as_bytes()).map_err(|e| format!("filesystem error: {}", e))
    }

    fn try_decode_vault(
        &self,
        recipient: &Recipient,
        priv_key: &dyn private::PrivateKey,
    ) -> Result<Vec<u8>, String> {
        let sym_key = priv_key.decrypt(&recipient.payload);
        if sym_key.is_err() {
            return Err("WARNING: Unable to decrypt vault symmetric key".to_string());
        }
        let sym_key = sym_key.unwrap();
        let sym_key = secretbox::Key::from_slice(&sym_key);
        if sym_key.is_none() {
            return Err("Invalid symmetric key decrypted".to_string());
        }
        let sym_key = sym_key.unwrap();

        let decrypted_contents = secretbox::open(&self.payload, &self.nonce, &sym_key);
        if decrypted_contents.is_err() {
            return Err("Unable to decrypt vault contents with symmetric key".to_string());
        }
        return Ok(decrypted_contents.unwrap());
    }

    pub fn unlock_vault(st: &mut state::State, path: &str) -> Result<Vec<u8>, String> {
        let vault = Vault::read_vault(path)?;
        for recipient in vault.recipients.iter() {
            if st
                .keys
                .unlocked
                .contains_key(recipient.pub_key.get_key_name())
            {
                let priv_key = st
                    .keys
                    .unlocked
                    .get(recipient.pub_key.get_key_name())
                    .unwrap();
                let decrypted_contents = vault.try_decode_vault(&recipient, priv_key.as_ref());
                if decrypted_contents.is_err() {
                    eprintln!("WARNING: {}", decrypted_contents.err().unwrap());
                    continue;
                }
                return decrypted_contents;
            }
        }

        for recipient in vault.recipients.iter() {
            let priv_key = st.keys.try_unlock(recipient.pub_key.get_key_name());
            if priv_key.is_none() {
                continue;
            }

            let priv_key = priv_key.unwrap();
            let decrypted_contents = vault.try_decode_vault(&recipient, priv_key);
            if decrypted_contents.is_err() {
                eprintln!("WARNING: {}", decrypted_contents.err().unwrap());
                continue;
            }
            return decrypted_contents;
        }

        return Err(format!("No keys able to unlock file: {}", path));
    }
}
