use super::public::PublicKey;
use super::public::PublicKeyWrapper;
use super::state;
use super::vault;
use crate::config;
use crate::constants;
use serde::Deserialize;
use serde::Serialize;
use serde_json;
use std::collections::HashMap;
use std::path::Path;
use std::time;

#[derive(Serialize, Deserialize)]
pub struct KeyChain {
    timestamp: u128,
    keys: Vec<PublicKeyWrapper>,
    paths: HashMap<String, Vec<String>>,
}

impl KeyChain {
    fn new() -> Self {
        let mut chain = KeyChain {
            timestamp: 0,
            keys: Vec::new(),
            paths: HashMap::new(),
        };
        chain.update_timestamp();
        chain
    }

    pub fn add_key(&mut self, key: PublicKeyWrapper) {
        let new_key_name = key.get_key_name();
        let mut replace = false;
        let mut index = 0;
        for (idx, key) in self.keys.iter().enumerate() {
            if key.get_key_name() == new_key_name {
                replace = true;
                index = idx;
            }
        }
        self.keys.push(key);
        if replace {
            self.keys.swap_remove(index);
        }
    }

    pub fn remove_key(&mut self, key_name: &str) {
        let mut index = 0;
        let mut found = false;
        for (idx, key) in self.keys.iter().enumerate() {
            if key.get_key_name() == key_name {
                index = idx;
                found = true;
            }
        }
        if found {
            self.keys.remove(index);
        }
    }

    pub fn write_chain(&mut self) {
        self.update_timestamp();
        let payload = serde_json::to_vec(self).unwrap();
        let recipients = self.keys.clone();
        vault::Vault::write_vault(&KeyChain::get_keychain_path(), &payload, recipients);
    }

    pub fn read_chain(st: &mut state::State) -> Result<Self, String> {
        let chain_path = Self::get_keychain_path();
        if !Path::new(&chain_path).exists() {
            return Ok(Self::new());
        }
        let payload = vault::Vault::unlock_vault(st, &chain_path)?;
        serde_json::from_slice(&payload)
            .map_err(|e| format!("Unable to read keychain vault: {}", e))
    }

    pub fn key_names_to_keys(&self, names: &[String]) -> Vec<PublicKeyWrapper> {
        let mut key_map: HashMap<String, PublicKeyWrapper> = HashMap::new();
        for key in self.keys.iter() {
            key_map.insert(key.get_key_name().to_string(), key.clone());
        }
        let mut keys = Vec::new();
        for name in names.iter() {
            if key_map.contains_key(name) {
                keys.push(key_map.get(name).unwrap().clone());
            }
        }
        keys
    }

    pub fn get_keys_for_path(&self, path: &str) -> Vec<PublicKeyWrapper> {
        let paths = get_path_breakdown(path);
        for part in paths {
            if self.paths.contains_key(part) {
                return self.key_names_to_keys(&self.paths.get(part).unwrap().clone());
            }
        }
        return self.keys.clone();
    }

    fn get_keychain_path() -> String {
        let store_directory = config::get_store_directory();
        let path = store_directory.join(constants::KEYCHAIN_FILE_NAME);
        path.as_os_str().to_str().unwrap().to_string()
    }

    fn update_timestamp(&mut self) {
        let now = time::SystemTime::now();
        let elapsed = now.duration_since(time::UNIX_EPOCH).unwrap();
        self.timestamp = elapsed.as_millis();
    }
}

fn get_path_breakdown(path: &str) -> Vec<&str> {
    let conv_path = Path::new(path);
    conv_path
        .ancestors()
        .map(|p| p.as_os_str().to_str().unwrap())
        .collect()
}
