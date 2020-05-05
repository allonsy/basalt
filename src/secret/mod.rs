pub mod decrypt;
pub mod encrypt;
pub mod reencrypt;

use crate::util::base32_decode;
use crate::util::base32_encode;
use serde::Deserialize;
use serde::Serialize;
use sodiumoxide::crypto::secretbox::Nonce;

pub use encrypt::encrypt_secret;

#[derive(Clone)]
struct SecretStore {
    nonce: Nonce,
    encrypted_payload: Vec<u8>,
    recipients: Vec<Recipient>,
}

#[derive(Clone)]
struct Recipient {
    device_id: String,
    encrypted_box: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SecretStoreFormat {
    nonce: String,
    encrypted_payload: String,
    recipients: Vec<RecipientFormat>,
}

#[derive(Serialize, Deserialize)]
struct RecipientFormat {
    device_id: String,
    encrypted_box: String,
}

impl SecretStoreFormat {
    fn new(store: SecretStore) -> SecretStoreFormat {
        SecretStoreFormat {
            nonce: base32_encode(&store.nonce.0),
            encrypted_payload: base32_encode(&store.encrypted_payload),
            recipients: store
                .recipients
                .into_iter()
                .map(|r| RecipientFormat::new(r))
                .collect(),
        }
    }

    fn into_secret_store(self) -> Option<SecretStore> {
        Some(SecretStore {
            nonce: Nonce::from_slice(&base32_decode(&self.nonce)?)?,
            encrypted_payload: base32_decode(&self.encrypted_payload)?,
            recipients: self
                .recipients
                .into_iter()
                .map(|r| r.into_recipient())
                .collect::<Option<Vec<Recipient>>>()?,
        })
    }
}

impl RecipientFormat {
    fn new(recipient: Recipient) -> RecipientFormat {
        RecipientFormat {
            device_id: recipient.device_id,
            encrypted_box: base32_encode(&recipient.encrypted_box),
        }
    }

    fn into_recipient(self) -> Option<Recipient> {
        Some(Recipient {
            device_id: self.device_id,
            encrypted_box: base32_decode(&self.encrypted_box)?,
        })
    }
}
