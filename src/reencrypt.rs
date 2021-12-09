use crate::client;
use crate::config;
use crate::keys::keyring;
use crate::keys::public;
use crate::vault::Vault;
use crate::vault::VaultKey;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

pub fn validate() -> Result<(), String> {
    let keychain = keyring::KeyChain::validate_keychain();

    let base_keys = keychain
        .validated_keys
        .iter()
        .map(|k| k.key.clone())
        .collect::<Vec<public::PublicKey>>();

    let base_path = config::get_store_dir();

    let client = client::Client::new()?;

    validate_dir(&base_path, &base_keys, &keychain, &client)?;

    Ok(())
}

fn validate_dir(
    dir_path: &Path,
    base_keys: &Vec<public::PublicKey>,
    keychain: &keyring::KeyChain,
    client: &client::Client,
) -> Result<(), String> {
    let mut keys = Vec::new();

    let key_id_file = dir_path.join(config::KEY_ID_FILE_NAME);
    let key_id_file = File::open(key_id_file);

    if key_id_file.is_ok() {
        let key_id_file = key_id_file.unwrap();
        let line_reader = BufReader::new(key_id_file);

        for line in line_reader.lines() {
            if line.is_ok() {
                let line = line.unwrap();
                let line = line.trim();
                let key = keychain.get_public_key_for_name(line);
                if key.is_some() {
                    keys.push(key.unwrap());
                } else if !line.is_empty() {
                    return Err(format!("No key found for keyid: {}", line));
                }
            }
        }
    } else {
        keys = base_keys.clone();
    }

    for entry in walkdir::WalkDir::new(dir_path) {
        if entry.is_ok() {
            let entry = entry.unwrap();

            if entry.file_type().is_file() {
                let vault_bytes = fs::read(entry.path());

                if vault_bytes.is_ok() {
                    let vault_bytes = vault_bytes.unwrap();

                    let parsed_vault = serde_json::from_slice(&vault_bytes);

                    if parsed_vault.is_ok() {
                        let parsed_vault: Vault = parsed_vault.unwrap();
                        let new_vault = validate_vault(&parsed_vault, &keys, client)?;

                        if new_vault.is_some() {
                            let new_vault = new_vault.unwrap();
                            new_vault.write_vault_raw(entry.path());
                        }
                    }
                }
            } else if entry.file_type().is_dir() {
                validate_dir(entry.path(), &keys, keychain, client);
            }
        }
    }

    Ok(())
}

fn validate_vault(
    vault: &Vault,
    target_keys: &Vec<public::PublicKey>,
    client: &client::Client,
) -> Result<Option<Vault>, String> {
    let mut current_keys = HashSet::new();
    let mut wanted_keys = HashSet::new();

    for target_key in target_keys {
        wanted_keys.insert(target_key.hash());
    }

    for key in vault.keys.iter() {
        current_keys.insert(key.get_hash());
    }

    for key in target_keys {
        if !current_keys.contains(&key.hash()) {
            return Ok(Some(reencrypt_vault(vault, target_keys)?));
        }
    }

    let mut new_vault = vault.clone();

    let mut changed = false;

    new_vault.keys = new_vault
        .keys
        .iter()
        .filter(|k| {
            if wanted_keys.contains(&k.get_hash()) {
                return true;
            } else {
                changed = true;
                return false;
            }
        })
        .map(|v| v.clone())
        .collect::<Vec<VaultKey>>();

    if changed {
        return Ok(Some(new_vault));
    }

    Ok(None)
}

fn reencrypt_vault(vault: &Vault, target_keys: &Vec<public::PublicKey>) -> Result<Vault, String> {
    let secret_key = vault
        .open_vault_secret()
        .map_err(|()| "unable to open vault".to_string())?;

    let mut new_keys = Vec::new();

    for key in target_keys {
        let payload = key.encrypt(&secret_key.0);
        new_keys.push(VaultKey::new(key.hash(), payload));
    }

    let mut new_vault = vault.clone();

    new_vault.keys = new_keys;

    Ok(new_vault)
}
