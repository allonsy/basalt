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

impl PaperKey {
    pub fn new(name: String) -> (String, Self) {
        let (pubkey, seckey) = box_::gen_keypair();
        let paper_sec_key = PaperKey::bytes_to_hex(&seckey.0);
        (
            paper_sec_key,
            PaperKey {
                name,
                enc_key: pubkey,
            },
        )
    }

    pub fn paperkey_to_seckey(bytestring: &str) -> Result<box_::SecretKey, String> {
        let bytes = PaperKey::hex_to_bytes(bytestring)?;
        box_::SecretKey::from_slice(&bytes).ok_or("Unable to decrypt paperkey".to_string())
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        let mut byte_string = String::new();
        for byte in bytes {
            byte_string += &format!("{:.02x}", byte);
        }
        byte_string
    }

    fn hex_to_bytes(input: &str) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        if input.len() % 2 != 0 {
            return Err("input string is malformed".to_string());
        }

        let mut byte_points = Vec::new();
        for (idx, ch) in input.chars().enumerate() {
            if idx % 2 == 0 {
                byte_points.push(format!("{}", ch));
            } else {
                byte_points[idx / 2] += &format!("{}", ch);
            }
        }

        for point in byte_points {
            bytes.push(
                point
                    .parse::<u8>()
                    .map_err(|e| format!("Unable to parse hex codepoint: {}", e))?,
            );
        }
        Ok(bytes)
    }
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
