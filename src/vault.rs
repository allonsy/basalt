use crate::client;
use crate::config;
use crate::keys::keyring;
use crate::keys::public::PublicKey;
use crate::util;
use serde::Deserialize;
use serde::Serialize;
use sodiumoxide::crypto::secretbox;
use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

#[derive(Serialize, Deserialize)]
struct Vault {
    ciphertext: Vec<u8>,
    nonce: secretbox::Nonce,
    keys: Vec<VaultKey>,
}

#[derive(Serialize, Deserialize)]
struct VaultKey {
    keyhash: String,
    payload: Vec<u8>,
}

impl Vault {
    pub fn create_vault(path: &Path, payload: Vec<u8>) {
        let nonce = secretbox::gen_nonce();
        let sym_key = secretbox::gen_key();

        let keys = get_keys_for_path(path);
        let mut vault_keys = Vec::new();

        for key in keys {
            vault_keys.push(VaultKey {
                keyhash: key.hash(),
                payload: key.encrypt(&sym_key.0),
            });
        }

        let ciphertext = secretbox::seal(&payload, &nonce, &sym_key);

        let vault = Vault {
            ciphertext,
            nonce,
            keys: vault_keys,
        };

        vault.write_vault(path);
    }

    pub fn open_vault(path: &Path) -> Result<Vec<u8>, ()> {
        let vault = Vault::read_vault(path);
        if vault.is_none() {
            return Err(());
        }
        let vault = vault.unwrap();

        let formatted_keys = vault
            .keys
            .iter()
            .map(|k| (k.keyhash.clone(), k.payload.clone()))
            .collect();

        let decrypted_key = client::decrypt(formatted_keys);
        if decrypted_key.is_err() {
            eprintln!("Unable to decrypt secret keys");
            return Err(());
        }
        let decrypted_key = decrypted_key.unwrap();
        let parsed_key = secretbox::Key::from_slice(&decrypted_key);
        if parsed_key.is_none() {
            eprintln!("Invalid key");
            return Err(());
        }
        let parsed_key = parsed_key.unwrap();

        secretbox::open(&vault.ciphertext, &vault.nonce, &parsed_key)
    }

    pub fn read_vault(path: &Path) -> Option<Self> {
        let mut store_dir = config::get_store_dir().join(path);

        let vault_bytes = fs::read(&store_dir);
        if vault_bytes.is_err() {
            eprintln!("Unable to read file: {:?}", store_dir);
            return None;
        }
        let vault_bytes = vault_bytes.unwrap();
        let parsed_vault = serde_json::from_slice(&vault_bytes);
        if parsed_vault.is_err() {
            eprintln!("Invalid store file: {:?}", store_dir);
            return None;
        }

        Some(parsed_vault.unwrap())
    }

    pub fn write_vault(&self, path: &Path) {
        let mut store_dir = config::get_store_dir().join(path);

        let vault_file = fs::File::create(&store_dir);
        if vault_file.is_err() {
            eprintln!("Unable to write to file: {:?}", store_dir);
            return;
        }
        let vault_file = vault_file.unwrap();

        let serialization_result = serde_json::to_writer(vault_file, self);

        if serialization_result.is_err() {
            eprintln!("Unable to serialize vault");
        }
    }
}

fn get_keys_for_path(path: &Path) -> Vec<PublicKey> {
    let mut keys = Vec::new();
    let path = path.canonicalize();
    if path.is_err() {
        return keys;
    }
    let path = path.unwrap().parent().map(|p| p.to_path_buf());
    if path.is_none() {
        return keys;
    }

    let keychain = keyring::KeyChain::validate_keychain();

    let store_dir = config::get_store_dir().canonicalize();
    if store_dir.is_err() {
        return keys;
    }

    let mut path = path.unwrap();
    let store_dir = store_dir.unwrap();

    while path != store_dir {
        let key_id_file = fs::File::open(path.join(config::KEY_ID_FILE_NAME));

        if key_id_file.is_ok() {
            let key_id_file = key_id_file.unwrap();
            let reader = BufReader::new(key_id_file);
            for line in reader.lines() {
                if line.is_ok() {
                    let line = line.unwrap();
                    let pubkey = keychain.get_public_key_for_name(&line);
                    if pubkey.is_none() {
                        util::exit(&format!("Cannot find valid key for key name: {}", line), 1);
                    }
                    keys.push(pubkey.unwrap());
                }
            }
            return keys;
        } else {
            let parent = path.parent();
            if parent.is_none() {
                return keys;
            }
            path = parent.unwrap().to_path_buf();
        }
    }

    keys
}
