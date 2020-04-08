use crate::keys::PublicKey;
use crate::util;
use serde_json::json;
use serde_json::value::Value;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::Nonce;

pub struct SecretStore {
    nonce: Nonce,
    encrypted_payload: Vec<u8>,
    recipients: Vec<Receiver>,
}

impl SecretStore {
    pub fn serialize(&self) -> Value {
        let recipients = Receiver::serialize_list(&self.recipients);
        json!({
            super::NONCE_KEY: util::base32_encode(&self.nonce.0),
            super::ENCRYPTED_PAYLOAD_KEY: util::base32_encode(&self.encrypted_payload),
            super::RECIPIENTS_KEY: recipients,
        })
    }
}

pub struct Receiver {
    device_id: String,
    encrypted_box: Vec<u8>,
}

impl Receiver {
    fn serialize(&self) -> Value {
        json!({
            super::DEVICE_ID_KEY: self.device_id,
            super::KEY_KEY: util::base32_encode(&self.encrypted_box)
        })
    }

    fn serialize_list(receivers: &Vec<Receiver>) -> Value {
        Value::Array(receivers.iter().map(|r| r.serialize()).collect())
    }
}

pub fn encrypt(payload: &str, keys: &Vec<Box<dyn PublicKey>>) -> SecretStore {
    let nonce = secretbox::gen_nonce();
    let symmetric_key = secretbox::gen_key();

    let enc_payload = secretbox::seal(payload.as_bytes(), &nonce, &symmetric_key);

    let mut recipients = Vec::new();
    for key in keys {
        recipients.push(Receiver {
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
