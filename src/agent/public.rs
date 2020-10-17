use serde::Deserialize;
use serde::Serialize;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sealedbox;

pub trait PublicKey {
    fn get_key_name(&self) -> &str;
    fn encrypt(&self, message: &[u8]) -> Vec<u8>;
}

#[derive(Serialize, Deserialize, Clone)]
pub enum PublicKeyWrapper {
    Sodium(SodiumKey),
    PaperKey(PaperKey),
    Yubikey(Yubikey),
}

impl PublicKeyWrapper {
    pub fn is_sodium(&self) -> bool {
        match self {
            PublicKeyWrapper::Sodium(_) => true,
            _ => false,
        }
    }

    pub fn is_paper(&self) -> bool {
        match self {
            PublicKeyWrapper::PaperKey(_) => true,
            _ => false,
        }
    }

    pub fn is_yubikey(&self) -> bool {
        match self {
            PublicKeyWrapper::Yubikey(_) => true,
            _ => false,
        }
    }
}

impl PublicKey for PublicKeyWrapper {
    fn get_key_name(&self) -> &str {
        match self {
            PublicKeyWrapper::Sodium(key) => key.get_key_name(),
            PublicKeyWrapper::PaperKey(key) => key.get_key_name(),
            PublicKeyWrapper::Yubikey(key) => key.get_key_name(),
        }
    }

    fn encrypt(&self, message: &[u8]) -> Vec<u8> {
        match self {
            PublicKeyWrapper::Sodium(key) => key.encrypt(message),
            PublicKeyWrapper::PaperKey(key) => key.encrypt(message),
            PublicKeyWrapper::Yubikey(key) => key.encrypt(message),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SodiumKey {
    pub name: String,
    pub enc_key: box_::PublicKey,
}

impl PublicKey for SodiumKey {
    fn get_key_name(&self) -> &str {
        &self.name
    }

    fn encrypt(&self, message: &[u8]) -> Vec<u8> {
        sealedbox::seal(message, &self.enc_key)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PaperKey {
    pub name: String,
    pub enc_key: box_::PublicKey,
}

impl PublicKey for PaperKey {
    fn get_key_name(&self) -> &str {
        &self.name
    }

    fn encrypt(&self, message: &[u8]) -> Vec<u8> {
        sealedbox::seal(message, &self.enc_key)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Yubikey {
    pub name: String,
    pub enc_key: box_::PublicKey,
    pub challenge: Vec<u8>,
}

impl PublicKey for Yubikey {
    fn get_key_name(&self) -> &str {
        &self.name
    }

    fn encrypt(&self, message: &[u8]) -> Vec<u8> {
        sealedbox::seal(message, &self.enc_key)
    }
}
