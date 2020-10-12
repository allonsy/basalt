use crate::config;
use glob::glob;
use serde::Deserialize;
use serde::Serialize;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::secretbox;
use std::fs;

pub trait PrivateKey {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String>;
}

#[derive(Serialize, Deserialize)]
pub struct SodiumPrivateKey {
    dec_key: box_::SecretKey,
}

impl SodiumPrivateKey {
    fn gen_key() -> SodiumPrivateKey {
        let (_, sec_key) = box_::gen_keypair();
        SodiumPrivateKey { dec_key: sec_key }
    }
}

impl PrivateKey for SodiumPrivateKey {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let pub_key = self.dec_key.public_key();
        let dec_res = sealedbox::open(ciphertext, &pub_key, &self.dec_key);
        dec_res.map_err(|_| "Unable to decrypt ciphertext".to_string())
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedSodiumKey {
    salt: pwhash::Salt,
    nonce: secretbox::Nonce,
    dec_key_cipher: Vec<u8>,
}

impl EncryptedSodiumKey {
    fn encrypt_key(key: &SodiumPrivateKey, pwd: &[u8]) -> Result<EncryptedSodiumKey, String> {
        let salt = pwhash::gen_salt();
        let nonce = secretbox::gen_nonce();
        let mut sym_key: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];

        pwhash::derive_key_interactive(&mut sym_key, pwd, &salt)
            .map_err(|_| "unable to allocated pwhash memory".to_string())?;
        let sym_key_formatted = secretbox::Key::from_slice(&sym_key).unwrap();
        let ciphertext = secretbox::seal(&key.dec_key.0, &nonce, &sym_key_formatted);
        Ok(EncryptedSodiumKey {
            salt,
            nonce,
            dec_key_cipher: ciphertext,
        })
    }

    fn decrypt_key(&self, pwd: &[u8]) -> Result<SodiumPrivateKey, String> {
        let mut sym_key: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];
        pwhash::derive_key_interactive(&mut sym_key, pwd, &self.salt)
            .map_err(|_| "Insufficient memory for hashing".to_string())?;
        let sym_key_formatted = secretbox::Key::from_slice(&sym_key).unwrap();
        let dec_key = secretbox::open(&self.dec_key_cipher, &self.nonce, &sym_key_formatted)
            .map_err(|_| "Unable to decrypt secret key".to_string())?;

        let dec_key_formatted = box_::SecretKey::from_slice(&dec_key)
            .ok_or("Invalid secret key decrypted".to_string())?;

        Ok(SodiumPrivateKey {
            dec_key: dec_key_formatted,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub enum DeviceKey {
    Encrypted(EncryptedSodiumKey),
    Unencrypted(SodiumPrivateKey),
}

impl DeviceKey {
    pub fn get_device_key_names() -> Vec<String> {
        let keys_dir = config::get_keys_directory();
        let pattern = format!("{}", keys_dir.join("*.key").display());
        let mut keys = Vec::new();
        let glob_res = glob(&pattern);
        if glob_res.is_err() {
            return keys;
        }

        let glob_res = glob_res.unwrap();
        for entry in glob_res {
            match entry {
                Ok(glob_match) => {
                    let device_name = glob_match.file_stem();
                    if device_name.is_some() {
                        let device_name = device_name.unwrap();
                        let device_name_str = device_name.to_str();
                        if device_name_str.is_some() {
                            keys.push(device_name_str.unwrap().to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        keys
    }

    pub fn write_key(&self, key_name: &str) {
        let json_bytes = serde_json::to_vec(&self);
        if json_bytes.is_err() {
            eprintln!(
                "Unable to serialize private key to json: {}",
                json_bytes.err().unwrap()
            );
            std::process::exit(1);
        }
        let json_bytes = json_bytes.unwrap();
        let fname = config::get_keys_directory().join(format!("{}.key", key_name));
        let write_res = fs::write(&fname, &json_bytes);
        if write_res.is_err() {
            eprintln!(
                "Unable to write private key to file: {}",
                write_res.err().unwrap()
            );
            std::process::exit(1);
        }
    }

    pub fn read_key(key_name: &str) -> DeviceKey {
        let fname = config::get_keys_directory().join(format!("{}.key", key_name));
        let json_bytes = fs::read(&fname);
        if json_bytes.is_err() {
            eprintln!(
                "Unable to read key {}: {}",
                key_name,
                json_bytes.err().unwrap()
            );
            std::process::exit(1);
        }
        let json_bytes = json_bytes.unwrap();

        let parsed_key = serde_json::from_slice(&json_bytes);
        if parsed_key.is_err() {
            eprintln!("Unable to parse key json: {}", parsed_key.err().unwrap());
            std::process::exit(1);
        }
        parsed_key.unwrap()
    }
}
