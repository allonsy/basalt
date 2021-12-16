use crate::client;
use crate::client::Client;
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

#[derive(Serialize, Deserialize, Clone)]
pub struct Vault {
    ciphertext: Vec<u8>,
    nonce: secretbox::Nonce,
    pub keys: Vec<VaultKey>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultKey {
    keyhash: String,
    payload: Vec<u8>,
}

impl VaultKey {
    pub fn new(hash: String, payload: Vec<u8>) -> Self {
        VaultKey {
            keyhash: hash,
            payload,
        }
    }

    pub fn get_hash(&self) -> String {
        self.keyhash.clone()
    }
}

impl Vault {
    pub fn create_vault(keychain: &keyring::KeyChain, path: &Path, payload: &[u8]) {
        let keys = get_keys_for_path(keychain, path);
        let vault = Vault::seal_vault(payload, keys);

        vault.write_vault(path);
    }

    pub fn seal_vault(payload: &[u8], keys: Vec<PublicKey>) -> Vault {
        let nonce = secretbox::gen_nonce();
        let sym_key = secretbox::gen_key();

        let mut vault_keys = Vec::new();

        for key in keys {
            vault_keys.push(VaultKey {
                keyhash: key.hash(),
                payload: key.encrypt(&sym_key.0),
            });
        }

        let ciphertext = secretbox::seal(&payload, &nonce, &sym_key);

        Vault {
            ciphertext,
            nonce,
            keys: vault_keys,
        }
    }

    pub fn open_vault_path(path: &Path) -> Result<Vec<u8>, ()> {
        let vault = Vault::read_vault(path);
        if vault.is_none() {
            return Err(());
        }
        let vault = vault.unwrap();

        vault.open_vault()
    }

    pub fn open_vault_secret(&self) -> Result<secretbox::Key, ()> {
        let formatted_keys = self
            .keys
            .iter()
            .map(|k| (k.keyhash.clone(), k.payload.clone()))
            .collect();
        let mut client = client::Client::new().map_err(|_| ())?;
        let decrypted_key = client.decrypt_message(formatted_keys);
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
        Ok(parsed_key.unwrap())
    }

    pub fn open_vault(&self) -> Result<Vec<u8>, ()> {
        let secret_key = self.open_vault_secret()?;
        secretbox::open(&self.ciphertext, &self.nonce, &secret_key)
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

    pub fn write_vault_raw(&self, path: &Path) {
        let vault_file = fs::File::create(&path);
        if vault_file.is_err() {
            eprintln!("Unable to write to file: {:?}", path);
            return;
        }
        let vault_file = vault_file.unwrap();

        let serialization_result = serde_json::to_writer(vault_file, self);

        if serialization_result.is_err() {
            eprintln!("Unable to serialize vault");
        }
    }

    pub fn write_vault(&self, path: &Path) {
        let store_dir = config::get_store_dir().join(path);

        self.write_vault_raw(&store_dir);
    }
}

fn get_keys_for_path(keychain: &keyring::KeyChain, path: &Path) -> Vec<PublicKey> {
    let store_dir_base = config::get_store_dir();
    let mut keys = Vec::new();
    let mut path = store_dir_base.join(path);
    if !path.is_dir() {
        let par_path = path.parent();
        if par_path.is_none() {
            return keys;
        }
        path = par_path.unwrap().to_path_buf();
    }
    let path = path.canonicalize();
    if path.is_err() {
        return keys;
    }

    let store_dir_par = config::get_store_dir().canonicalize();
    if store_dir_par.is_err() {
        return keys;
    }

    let store_dir_par = store_dir_par.unwrap();
    if store_dir_par.parent().is_none() {
        return keys;
    }

    let mut path = path.unwrap();
    let store_dir_par = store_dir_par.parent().unwrap().to_path_buf();

    while path != store_dir_par {
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

    keychain
        .validated_keys
        .iter()
        .map(|k| k.key.clone())
        .collect()
}
