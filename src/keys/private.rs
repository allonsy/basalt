use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::sign;
use std::fs;
use std::path::Path;

#[derive(Clone, Serialize, Deserialize)]
struct SodiumPrivateKey {
    enc_key: box_::SecretKey,
    sign_key: sign::SecretKey,
}

#[derive(Clone, Serialize, Deserialize)]
enum PrivateKeyType {
    Sodium(SodiumPrivateKey),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateKey {
    name: String,
    key: PrivateKeyType,
}

impl PrivateKey {
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        match &self.key {
            PrivateKeyType::Sodium(key) => {
                let pubkey = key.enc_key.public_key();
                sealedbox::open(ciphertext, &pubkey, &key.enc_key)
            }
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match &self.key {
            PrivateKeyType::Sodium(key) => sign::sign(message, &key.sign_key),
        }
    }
}

enum OnDiskPrivateKey {
    UnencryptedKey(PrivateKey),
    EncryptedKey(EncryptedPrivateKey),
}

impl OnDiskPrivateKey {
    fn is_encrypted(&self) -> bool {
        match self {
            OnDiskPrivateKey::EncryptedKey(_) => true,
            _ => false,
        }
    }
    fn decrypt_key(self, passphrase: &[u8]) -> Result<PrivateKey, String> {
        match self {
            OnDiskPrivateKey::UnencryptedKey(key) => Ok(key),
            OnDiskPrivateKey::EncryptedKey(key) => key.decrypt_key(passphrase),
        }
    }

    fn encrypt_key(key: &PrivateKey, passphrase: &[u8]) -> Self {
        OnDiskPrivateKey::EncryptedKey(EncryptedPrivateKey::encrypt_key(key, passphrase))
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct EncryptedPrivateKey {
    nonce: secretbox::Nonce,
    salt: pwhash::Salt,
    ciphertext: Vec<u8>,
}

impl EncryptedPrivateKey {
    fn encrypt_key(privkey: &PrivateKey, passphrase: &[u8]) -> Self {
        let salt = pwhash::gen_salt();
        let nonce = secretbox::gen_nonce();
        let mut key: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];

        pwhash::derive_key_interactive(&mut key, passphrase, &salt);

        let key_payload = serde_json::to_vec(privkey).expect("Unable to serialize private key");

        let ciphertext = secretbox::seal(
            &key_payload,
            &nonce,
            &secretbox::Key::from_slice(&key).unwrap(),
        );

        Self {
            nonce,
            salt,
            ciphertext,
        }
    }

    fn decrypt_key(self, passphrase: &[u8]) -> Result<PrivateKey, String> {
        let mut key = [0; secretbox::KEYBYTES];

        pwhash::derive_key_interactive(&mut key, passphrase, &self.salt);

        let key_payload = secretbox::open(
            &self.ciphertext,
            &self.nonce,
            &secretbox::Key::from_slice(&key).unwrap(),
        )
        .map_err(|()| "Unable to decrypt secret key".to_string())?;

        serde_json::from_slice(&key_payload)
            .map_err(|_| "Unable to parse decrypted key".to_string())
    }

    pub fn write_key(&self, path: &Path) {
        let payload = serde_json::to_vec(self).expect("Unable to serialize key");

        fs::write(path, payload).expect("Unable to write public key");
    }

    pub fn read_key(path: &Path) -> Result<Self, String> {
        let payload = fs::read(path).map_err(|_| "unable to read private key file".to_string())?;

        serde_json::from_slice(&payload).map_err(|_| "unable to parse public key".to_string())
    }
}
