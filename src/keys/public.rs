use serde::Deserialize;
use serde::Serialize;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::sign;
use std::fs;
use std::path::Path;

#[derive(Clone, Serialize, Deserialize)]
struct SodiumPublicKey {
    enc_key: box_::PublicKey,
    sign_key: sign::PublicKey,
}

#[derive(Clone, Serialize, Deserialize)]
enum PublicKeyType {
    Sodium(SodiumPublicKey),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKey {
    name: String,
    key: PublicKeyType,
}

impl PublicKey {
    pub fn encrypt(&self, content: &[u8]) -> Vec<u8> {
        match &self.key {
            PublicKeyType::Sodium(key) => sealedbox::seal(content, &key.enc_key),
        }
    }

    pub fn verify(&self, signature: &sign::Signature, content: &[u8]) -> bool {
        match &self.key {
            PublicKeyType::Sodium(key) => sign::verify_detached(signature, content, &key.sign_key),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum SignatureKey {
    Sodium(box_::PublicKey),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeySignature {
    key: SignatureKey,
    payload: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FullPublicKey {
    key: PublicKey,
    signatures: Vec<KeySignature>,
}

impl FullPublicKey {
    pub fn new(key: &PublicKey) -> FullPublicKey {
        FullPublicKey {
            key: key.clone(),
            signatures: Vec::new(),
        }
    }

    pub fn write_key(&self, path: &Path) {
        let payload = serde_json::to_vec(self).expect("Unable to serialize key");

        fs::write(path, payload).expect("Unable to write public key");
    }
}
