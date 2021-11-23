use crate::config;
use crate::util;
use serde::Deserialize;
use serde::Serialize;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::hash as cryptohash;
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::sign;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

#[derive(Clone, Serialize, Deserialize)]
struct SodiumPublicKey {
    enc_key: box_::PublicKey,
    sign_key: sign::PublicKey,
}

#[derive(Clone, Serialize, Deserialize)]
enum PublicKeyType {
    Sodium(SodiumPublicKey),
}

impl PublicKeyType {
    fn get_sign_payload(&self) -> Vec<u8> {
        match self {
            PublicKeyType::Sodium(key) => {
                let mut bytes = Vec::new();
                bytes.extend_from_slice(&key.enc_key.0);
                bytes.extend_from_slice(&key.sign_key.0);
                bytes
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PublicKey {
    name: String,
    key: PublicKeyType,
}

impl PublicKey {
    pub fn new_sodium_key(
        name: String,
        enc_key: box_::PublicKey,
        sign_key: sign::PublicKey,
    ) -> Self {
        PublicKey {
            name,
            key: PublicKeyType::Sodium(SodiumPublicKey { enc_key, sign_key }),
        }
    }

    pub fn encrypt(&self, content: &[u8]) -> Vec<u8> {
        match &self.key {
            PublicKeyType::Sodium(key) => sealedbox::seal(content, &key.enc_key),
        }
    }

    pub fn verify(&self, signature: &[u8], content: &[u8]) -> bool {
        let mut sodium_signature: [u8; sign::SIGNATUREBYTES] = [0; sign::SIGNATUREBYTES];
        if signature.len() != sign::SIGNATUREBYTES {
            return false;
        }

        for (idx, val) in signature.iter().enumerate() {
            sodium_signature[idx] = *val;
        }

        let sodium_signature = sign::Signature::new(sodium_signature);
        match &self.key {
            PublicKeyType::Sodium(key) => {
                sign::verify_detached(&sodium_signature, content, &key.sign_key)
            }
        }
    }

    pub fn hash(&self) -> String {
        match &self.key {
            PublicKeyType::Sodium(key) => {
                let mut key_vec = Vec::new();

                key_vec.extend_from_slice(&key.enc_key.0);
                key_vec.extend_from_slice(&key.sign_key.0);

                let mut hash_bytes = Vec::new();
                hash_bytes.extend_from_slice(&cryptohash::hash(&key_vec).0);
                util::hexify(&hash_bytes)
            }
        }
    }

    pub fn get_sign_payload(&self) -> Vec<u8> {
        self.key.get_sign_payload()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeySignature {
    pub key_hash: String,
    pub payload: Vec<u8>,
}

impl KeySignature {
    pub fn new(key_hash: String, payload: Vec<u8>) -> Self {
        KeySignature { key_hash, payload }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FullPublicKey {
    pub key: PublicKey,
    pub signatures: Vec<KeySignature>,
}

impl FullPublicKey {
    pub fn new(key: &PublicKey) -> FullPublicKey {
        FullPublicKey {
            key: key.clone(),
            signatures: Vec::new(),
        }
    }

    pub fn get_key_path(&self) -> PathBuf {
        config::get_public_keys_dir().join(format!("{}.pub", self.key.name))
    }

    pub fn write_key(&self) {
        let payload = serde_json::to_vec(self).expect("Unable to serialize key");
        let path = self.get_key_path();

        fs::write(path, payload).expect("Unable to write public key");
    }

    pub fn read_key(path: &Path) -> Result<Self, String> {
        let payload = fs::read(path).map_err(|_| "unable to read public key file".to_string())?;

        serde_json::from_slice(&payload).map_err(|_| "unable to parse public key".to_string())
    }
}
