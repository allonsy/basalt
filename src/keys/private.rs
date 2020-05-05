use super::public;
use super::public::get_head;
use super::public::ChainLink;
use super::public::KeyChain;
use super::public::KeyEvent;
use super::public::KeyEventSignature;
use super::public::PublicKey;
use super::public::PublicKeyWrapper;
use super::public::SodiumKey;
use crate::agent::client;
use crate::agent::pinentry;
use crate::config;
use crate::util;
use glob::glob;
use serde::Deserialize;
use serde::Serialize;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::pwhash::Salt;
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::Nonce;
use sodiumoxide::crypto::sign;
use std::fs;

#[derive(Serialize, Deserialize)]
pub struct PrivateKeyWrapper {
    pub device_id: String,
    pub key: PrivateKey,
}

#[derive(Serialize, Deserialize)]
pub enum PrivateKey {
    Sodium(SodiumPrivateKey),
}

impl PrivateKey {
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            PrivateKey::Sodium(SodiumPrivateKey::Unencrypted(skey)) => {
                Ok(sign::sign_detached(message, &skey.sign_key).0.to_vec())
            }
            _ => Err("private key doesn't support sign operations".to_string()),
        }
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            PrivateKey::Sodium(SodiumPrivateKey::Unencrypted(skey)) => {
                let pub_key = skey.encrypt_key.public_key();
                let plaintext = sealedbox::open(ciphertext, &pub_key, &skey.encrypt_key);
                plaintext.map_err(|_| "decrypt operation failure".to_string())
            }
            _ => Err("private key doesn't support decrypt operations".to_string()),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum SodiumPrivateKey {
    Encrypted(EncryptedSodiumPrivateKey),
    Unencrypted(UnencryptedSodiumPrivateKey),
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedSodiumPrivateKey {
    encrypt_salt: Salt,
    encrypt_nonce: Nonce,
    encrypt_key: Vec<u8>,
    sign_salt: Salt,
    sign_nonce: Nonce,
    sign_key: Vec<u8>,
}

impl EncryptedSodiumPrivateKey {
    fn new(
        pin: &str,
        e_asym_key: box_::SecretKey,
        s_asym_key: sign::SecretKey,
    ) -> EncryptedSodiumPrivateKey {
        let e_salt = pwhash::gen_salt();
        let e_nonce = secretbox::gen_nonce();
        let mut e_key = [0; secretbox::KEYBYTES];
        pwhash::derive_key_interactive(&mut e_key, pin.as_bytes(), &e_salt).unwrap();
        let e_key = secretbox::Key::from_slice(&e_key).unwrap();
        let encrypted_e_key = secretbox::seal(&e_asym_key.0, &e_nonce, &e_key);

        let s_salt = pwhash::gen_salt();
        let s_nonce = secretbox::gen_nonce();
        let mut s_key = [0; secretbox::KEYBYTES];
        pwhash::derive_key_interactive(&mut s_key, pin.as_bytes(), &s_salt).unwrap();
        let s_key = secretbox::Key::from_slice(&s_key).unwrap();
        let encrypted_s_key = secretbox::seal(&s_asym_key.0, &s_nonce, &s_key);

        EncryptedSodiumPrivateKey {
            encrypt_salt: e_salt,
            encrypt_nonce: e_nonce,
            encrypt_key: encrypted_e_key,
            sign_salt: s_salt,
            sign_nonce: s_nonce,
            sign_key: encrypted_s_key,
        }
    }

    pub fn decrypt_key(&self, pwd: &str) -> Option<UnencryptedSodiumPrivateKey> {
        let enc_key = decrypt_key_param(
            &self.encrypt_key,
            pwd,
            &self.encrypt_salt,
            &self.encrypt_nonce,
        )?;
        let sign_key =
            decrypt_key_param(&self.encrypt_key, pwd, &self.sign_salt, &self.sign_nonce)?;

        Some(UnencryptedSodiumPrivateKey {
            encrypt_key: box_::SecretKey::from_slice(&enc_key)?,
            sign_key: sign::SecretKey::from_slice(&sign_key)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct UnencryptedSodiumPrivateKey {
    encrypt_key: box_::SecretKey,
    sign_key: sign::SecretKey,
}

pub fn get_device_keys() -> Vec<PrivateKeyWrapper> {
    let keys_dir = config::get_keys_dir();
    let glob_path = keys_dir.join("*.sec");
    let mut device_keys = Vec::new();

    let key_glob = glob(glob_path.to_str().unwrap());
    if key_glob.is_err() {
        return device_keys;
    }
    let key_glob = key_glob.unwrap();

    for key_path in key_glob {
        if key_path.is_err() {
            continue;
        }
        let key_path = key_path.unwrap();
        let contents = fs::read_to_string(key_path);
        if contents.is_err() {
            continue;
        }
        let contents = contents.unwrap();

        let sec_key = serde_json::from_str(&contents);
        if sec_key.is_ok() {
            device_keys.push(sec_key.unwrap());
        }
    }
    device_keys
}

fn decrypt_key_param(payload: &[u8], pwd: &str, salt: &Salt, nonce: &Nonce) -> Option<Vec<u8>> {
    let mut symmetric_key = [0; secretbox::KEYBYTES];
    pwhash::derive_key_interactive(&mut symmetric_key, pwd.as_bytes(), salt).unwrap();
    let symmetric_key = secretbox::Key::from_slice(&symmetric_key).unwrap();
    secretbox::open(payload, nonce, &symmetric_key).ok()
}

pub fn generate_key(keychain: &mut KeyChain) {
    let mut device_id: String;
    loop {
        device_id = util::prompt_user("Please enter a device name");
        if !keychain.is_valid_device_id(&device_id) {
            break;
        }
    }
    let key_type_choices = vec!["sodium"];
    let key_type_choice = util::user_menu("Please choose a key type", &key_type_choices, Some(0));
    match key_type_choices[key_type_choice] {
        "sodium" => generate_sodium_key(&device_id, keychain),
        _ => panic!("Unknown user choice"),
    }
}

fn generate_sodium_key(device_id: &str, keychain: &mut KeyChain) {
    let (pub_enc_key, sec_enc_key) = box_::gen_keypair();
    let (pub_sign_key, sec_sign_key) = sign::gen_keypair();
    let pubkey_wrapper = PublicKeyWrapper {
        device_id: device_id.to_string(),
        key: PublicKey::Sodium(SodiumKey {
            enc_key: pub_enc_key,
            sign_key: pub_sign_key,
        }),
    };

    if keychain.is_empty() {
        let new_key_event = KeyEvent::NewKey(pubkey_wrapper);
        let sig_message = util::concat(&keychain.get_digest(), &new_key_event.get_digest());
        let sig_payload = sign::sign_detached(&sig_message, &sec_sign_key).0.to_vec();
        let sig = KeyEventSignature {
            signing_key_id: device_id.to_string(),
            payload: sig_payload,
        };
        let new_link = ChainLink {
            parent: Vec::new(),
            event: new_key_event,
            signature: sig,
        };
        public::write_head(&new_link.get_digest());
        keychain.chain.push(new_link);
    } else {
        let head = get_head();
        let trusted_keys = keychain.verify(head);
        if trusted_keys.is_none() {
            eprintln!("Invalid keychain detected");
            std::process::exit(1);
        }
        let trusted_keys = trusted_keys.unwrap();
        let trusted_device_keys = get_device_keys();
        let mut signers = Vec::new();
        let mut signer_keys = Vec::new();
        for device_key in trusted_device_keys {
            if trusted_keys.contains_key(&device_key.device_id) {
                signers.push(format!("{} (device key)", device_key.device_id));
                signer_keys.push(device_key.device_id);
            }
        }
        signers.push("another device".to_string());
        signer_keys.push("another device".to_string());
        loop {
            let option: String;
            let key_option: String;
            if signers.len() == 1 {
                option = signers[0].clone();
                key_option = signer_keys[0].clone();
            } else {
                let user_option = util::user_menu(
                    "Please choose a device/key to sign your new key",
                    &signers.iter().map(|s| s.as_str()).collect::<Vec<&str>>(),
                    Some(0),
                );
                option = signers[user_option].clone();
                key_option = signer_keys[user_option].clone();
            }

            if option == "another device" {
                let new_key_event = KeyEvent::KeySignRequest(pubkey_wrapper.clone());
                let sig_message = util::concat(&keychain.get_digest(), &new_key_event.get_digest());
                let sig_payload = sign::sign_detached(&sig_message, &sec_sign_key).0.to_vec();
                let sig = KeyEventSignature {
                    signing_key_id: device_id.to_string(),
                    payload: sig_payload,
                };
                let new_link = ChainLink {
                    parent: keychain.get_digest(),
                    event: new_key_event,
                    signature: sig,
                };
                keychain.chain.push(new_link);
                break;
            } else {
                let signer_id = key_option;
                let new_key_event = KeyEvent::NewKey(pubkey_wrapper.clone());
                let sign_message =
                    util::concat(&keychain.get_digest(), &new_key_event.get_digest());
                let sig_payload = client::sign(&signer_id, &sign_message);
                if sig_payload.is_err() {
                    println!(
                        "Signing with desired key failed: {}",
                        sig_payload.err().unwrap()
                    );
                    continue;
                }
                let sig = KeyEventSignature {
                    signing_key_id: signer_id,
                    payload: sig_payload.unwrap(),
                };
                let new_link = ChainLink {
                    parent: keychain.get_digest(),
                    event: new_key_event,
                    signature: sig,
                };
                keychain.chain.push(new_link);
                break;
            }
        }
    }
    write_private_key(device_id, sec_enc_key, sec_sign_key);
}

fn write_private_key(device_id: &str, e_key: box_::SecretKey, s_key: sign::SecretKey) {
    let pin_res = pinentry::generate_pin(device_id);
    let pin = if pin_res.is_err() {
        eprintln!("PIN Entry failed, storing unencrypted");
        String::new()
    } else {
        pin_res.unwrap()
    };

    let secret_key: SodiumPrivateKey = if pin.is_empty() {
        SodiumPrivateKey::Unencrypted(UnencryptedSodiumPrivateKey {
            encrypt_key: e_key,
            sign_key: s_key,
        })
    } else {
        SodiumPrivateKey::Encrypted(EncryptedSodiumPrivateKey::new(&pin, e_key, s_key))
    };

    let secret_key_wrapper = PrivateKeyWrapper {
        device_id: device_id.to_string(),
        key: PrivateKey::Sodium(secret_key),
    };

    let private_key_bytes = serde_json::to_string(&secret_key_wrapper).unwrap();
    let private_key_path = config::get_keys_dir().join(format!("{}.sec", device_id));
    fs::write(private_key_path, &private_key_bytes).unwrap();
}
