use super::KeySignature;
use super::PrivateKey;
use super::PublicKey;
use crate::util;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::hash;
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::sign;

pub fn generate_new_sodium_key(device_id: &str) -> (SodiumPublicKey, SodiumPrivateKey) {
    let sec_key = SodiumPrivateKey::generate(device_id.to_string());
    let signatures = Vec::new();
    let enc_pub_key = sec_key.get_enc_key().public_key();
    let sign_pub_key = sec_key.get_sign_key().public_key();
    let pub_key =
        SodiumPublicKey::new(device_id.to_string(), enc_pub_key, sign_pub_key, signatures);
    (pub_key, sec_key)
}

pub struct SodiumPublicKey {
    device_id: String,
    enc_key: box_::PublicKey,
    sign_key: sign::PublicKey,
    signatures: Vec<KeySignature>,
}

impl SodiumPublicKey {
    pub fn new(
        device_id: String,
        enc_key: box_::PublicKey,
        sign_key: sign::PublicKey,
        signatures: Vec<KeySignature>,
    ) -> SodiumPublicKey {
        SodiumPublicKey {
            device_id,
            enc_key,
            sign_key,
            signatures,
        }
    }

    pub fn get_enc_key(&self) -> &box_::PublicKey {
        &self.enc_key
    }

    pub fn get_sign_key(&self) -> &sign::PublicKey {
        &self.sign_key
    }
}

impl PublicKey for SodiumPublicKey {
    fn get_device_id(&self) -> &str {
        &self.device_id
    }

    fn get_digest(&self) -> Vec<u8> {
        let device_id_bytes = self.device_id.as_bytes();
        let digest_bytes = util::concat(device_id_bytes, &self.enc_key.0);
        let digest_bytes = util::concat(&digest_bytes, &self.sign_key.0);
        hash::hash(&digest_bytes).0.to_vec()
    }

    fn verify(&self, signed_message: &[u8], expected: &[u8]) -> bool {
        let res = sign::verify(signed_message, &self.sign_key);
        if res.is_ok() {
            let mut expected_vec = Vec::new();
            expected_vec.extend_from_slice(expected);
            if expected_vec == res.unwrap() {
                return true;
            }
        }
        false
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        sealedbox::seal(plaintext, &self.enc_key)
    }

    fn get_signatures(&self) -> &Vec<KeySignature> {
        &self.signatures
    }
}

pub struct SodiumPrivateKey {
    device_id: String,
    enc_private_key: box_::SecretKey,
    sign_private_key: sign::SecretKey,
}

impl SodiumPrivateKey {
    pub fn new(
        device_id: String,
        enc_private_key: box_::SecretKey,
        sign_private_key: sign::SecretKey,
    ) -> SodiumPrivateKey {
        SodiumPrivateKey {
            device_id,
            enc_private_key,
            sign_private_key,
        }
    }

    pub fn generate(device_id: String) -> SodiumPrivateKey {
        let (_, esk) = box_::gen_keypair();
        let (_, ssk) = sign::gen_keypair();
        SodiumPrivateKey {
            device_id,
            enc_private_key: esk,
            sign_private_key: ssk,
        }
    }

    pub fn get_enc_key(&self) -> &box_::SecretKey {
        &self.enc_private_key
    }

    pub fn get_sign_key(&self) -> &sign::SecretKey {
        &self.sign_private_key
    }
}

impl PrivateKey for SodiumPrivateKey {
    fn get_device_id(&self) -> &str {
        &self.device_id
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        sign::sign(message, &self.sign_private_key)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
        let enc_pub_key = self.enc_private_key.public_key();
        sealedbox::open(ciphertext, &enc_pub_key, &self.enc_private_key)
    }
}
