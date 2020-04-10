pub mod sodium;
use crate::util;
pub use sodium::SodiumPrivateKey;
pub use sodium::SodiumPublicKey;

pub const KEY_TYPES: &'static [&'static str] = &["Sodium"];

pub struct KeySignature {
    pub public_key_id: String,
    pub signing_key_id: String,
    pub signature: Vec<u8>,
}

impl KeySignature {
    pub fn new(public_key_id: String, signing_key_id: String, signature: Vec<u8>) -> KeySignature {
        KeySignature {
            public_key_id,
            signing_key_id,
            signature,
        }
    }

    pub fn verify_signature(
        &self,
        public_key: Box<dyn PublicKey>,
        signing_key: Box<dyn PublicKey>,
    ) -> bool {
        if public_key.get_device_id() != self.public_key_id {
            return false;
        }
        if signing_key.get_device_id() != self.signing_key_id {
            return false;
        }

        let prefix_bytes = "sign_key".as_bytes();
        let digest_bytes = public_key.get_digest();
        let signature_bytes = util::concat(prefix_bytes, &digest_bytes);

        signing_key.verify(&self.signature, &signature_bytes)
    }
}

pub trait PublicKey {
    fn get_device_id(&self) -> &str;
    fn get_digest(&self) -> Vec<u8>;
    fn verify(&self, signed_message: &[u8], expected: &[u8]) -> bool;
    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>;
    fn get_signatures(&self) -> &Vec<KeySignature>;
}

pub trait PrivateKey {
    fn get_device_id(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Vec<u8>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ()>;
}
