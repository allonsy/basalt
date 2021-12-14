use super::public;
use crate::agent;
use crate::client;
use crate::client::Client;
use crate::config;
use crate::menu;
use glob::glob;
use std::collections::HashMap;

pub fn get_public_keys() -> Vec<public::FullPublicKey> {
    let mut pub_key_dir = config::get_public_keys_dir();
    pub_key_dir.push("*.pub");

    let mut pub_keys = Vec::new();

    let glob_matches = glob(pub_key_dir.to_str().unwrap());
    if let Err(e) = glob_matches {
        eprintln!("Unable to read public key directory: {}", e);
        return pub_keys;
    }

    let glob_matches = glob_matches.unwrap();

    for entry in glob_matches {
        match entry {
            Ok(file_path) => {
                let parsed_priv_key = public::FullPublicKey::read_key(&file_path);
                match parsed_priv_key {
                    Ok(key) => pub_keys.push(key),
                    Err(e) => eprintln!("Unable to read public key: {}", e),
                };
            }
            Err(e) => eprintln!("Unable to read public key: {}", e),
        }
    }

    pub_keys
}

fn is_trusted(
    pubkey: &public::FullPublicKey,
    trusted_keys: &HashMap<String, public::FullPublicKey>,
) -> bool {
    for signature in &pubkey.signatures {
        if trusted_keys.contains_key(&signature.key_hash) {
            let signing_key = trusted_keys.get(&signature.key_hash).unwrap();
            if signing_key
                .key
                .verify(&signature.payload, &pubkey.key.get_sign_payload())
            {
                return true;
            }
        }
    }

    false
}

pub struct KeyChain {
    pub validated_keys: Vec<public::FullPublicKey>,
    unvalidated_keys: Vec<public::FullPublicKey>,
}

impl KeyChain {
    pub fn validate_keychain() -> Self {
        let public_keys = get_public_keys();
        let device_keys = agent::get_device_keys();

        let mut trusted_keys = HashMap::new();

        for key in device_keys {
            trusted_keys.insert(
                key.hash(),
                public::FullPublicKey::new(&key.get_public_key()),
            );
        }

        let mut untrusted_keys = public_keys;

        loop {
            let mut changed = false;

            let mut index = 0;
            while index < untrusted_keys.len() {
                let key = &untrusted_keys[index];
                if trusted_keys.contains_key(&key.key.hash()) || is_trusted(&key, &trusted_keys) {
                    let removed_key = untrusted_keys.remove(index);
                    trusted_keys.insert(removed_key.key.hash(), removed_key);
                    changed = true;
                } else {
                    index += 1;
                }
            }

            if changed == false {
                break;
            }
        }

        let client = Client::new();

        if client.is_ok() {
            let mut client = client.unwrap();
            sign_key(&mut untrusted_keys, &mut client);
        }

        KeyChain {
            validated_keys: trusted_keys.into_values().collect(),
            unvalidated_keys: untrusted_keys,
        }
    }

    pub fn get_public_key_for_name(&self, name: &str) -> Option<public::PublicKey> {
        for key in &self.validated_keys {
            if key.key.name == name {
                return Some(key.key.clone());
            }
        }
        None
    }

    pub fn get_public_key_for_hash(&self, hash: &str) -> Option<public::PublicKey> {
        for key in &self.validated_keys {
            if key.key.hash() == hash {
                return Some(key.key.clone());
            }
        }

        None
    }
}

pub fn sign_key(
    pubkeys: &mut Vec<public::FullPublicKey>,
    client: &mut Client,
) -> Vec<public::FullPublicKey> {
    let mut untrusted_keys = Vec::new();

    for key in pubkeys {
        let prompt = format!(
            "The following key is untrusted: {}, do you wish to sign it?",
            key.key.hash()
        );
        let should_sign = menu::prompt_yes_no(prompt, Some(true));

        if should_sign {
            let sign_res = client.sign_message(key.key.get_sign_payload());
            if sign_res.is_err() {
                eprintln!("Unable to sign key");
                untrusted_keys.push(key.clone());
            } else {
                let (keyhash, payload) = sign_res.unwrap();
                key.signatures
                    .push(public::KeySignature::new(keyhash, payload));
                key.write_key();
            }
        } else {
            untrusted_keys.push(key.clone());
        }
    }

    untrusted_keys
}
