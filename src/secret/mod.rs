mod decrypt;
mod encrypt;

use serde::Deserialize;
use serde::Serialize;
use sodiumoxide::crypto::secretbox::Nonce;

pub use encrypt::encrypt;

#[derive(Serialize, Deserialize)]
pub struct SecretStore {
    nonce: Nonce,
    encrypted_payload: Vec<u8>,
    recipients: Vec<Recipient>,
}

#[derive(Serialize, Deserialize)]
pub struct Recipient {
    device_id: String,
    encrypted_box: Vec<u8>,
}
