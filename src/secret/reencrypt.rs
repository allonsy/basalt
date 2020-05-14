use super::decrypt;
use super::encrypt;
use super::SecretStore;
use crate::agent::client;
use crate::config;
use crate::keys::private;
use crate::keys::public;
use crate::keys::public::PublicKey;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

pub fn reencrypt_path(path: &str) {
    let full_path = config::get_store_dir().join(path);
    let path = PathBuf::from(path);
    let head = public::get_head();
    let keychain = public::KeyChain::get_keychain();
    if keychain.is_err() {
        eprintln!("Unable to read keychain: {}", keychain.err().unwrap());
        return;
    }
    let keychain = keychain.unwrap();
    let trusted_keys = keychain.verify(head);
    if trusted_keys.is_none() {
        eprintln!("Keychain is invalid");
        return;
    }
    let trusted_keys = trusted_keys.unwrap();

    let mut to_encrypt = Vec::new();
    let mut new_recipients = Vec::new();

    if full_path.is_file() {
        reencrypt_file(
            &full_path,
            &path,
            &trusted_keys,
            &mut to_encrypt,
            &mut new_recipients,
        );
    } else if full_path.is_dir() {
        reencrypt_dir(
            &full_path,
            &path,
            &trusted_keys,
            &mut to_encrypt,
            &mut new_recipients,
        );
    }

    submit_reencryption(&trusted_keys, &to_encrypt, &new_recipients);
}

fn reencrypt_dir(
    path: &Path,
    local_path: &Path,
    trusted_keys: &HashMap<String, &PublicKey>,
    to_encrypt: &mut Vec<(PathBuf, SecretStore)>,
    new_recipients: &mut Vec<Vec<String>>,
) {
    let dir = path.read_dir();
    if dir.is_err() {
        eprintln!("Unable to read directory: {}", dir.err().unwrap());
        return;
    }
    let dir_name = path.file_name().unwrap();
    let dir = dir.unwrap();
    for entry in dir {
        if entry.is_err() {
            eprintln!(
                "Unable to read sub_directory item: {}",
                entry.err().unwrap()
            );
            continue;
        }
        let entry_path = entry.unwrap().path();
        let is_hidden = entry_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with(".");
        if entry_path.is_file() && !is_hidden {
            reencrypt_file(
                &entry_path,
                &local_path.join(dir_name),
                trusted_keys,
                to_encrypt,
                new_recipients,
            );
        } else if entry_path.is_dir() && !is_hidden {
            reencrypt_dir(
                &entry_path,
                &local_path.join(dir_name),
                trusted_keys,
                to_encrypt,
                new_recipients,
            );
        }
    }
}

fn reencrypt_file(
    path: &Path,
    local_path: &Path,
    trusted_keys: &HashMap<String, &PublicKey>,
    to_encrypt: &mut Vec<(PathBuf, SecretStore)>,
    new_recipients: &mut Vec<Vec<String>>,
) {
    let current_store = parse_file(path);
    if current_store.is_err() {
        eprintln!("{}", current_store.err().unwrap());
        return;
    }
    let mut current_store = current_store.unwrap();

    let target_recipients = encrypt::load_keys_for_file(local_path);
    if target_recipients.is_err() {
        eprintln!("{}", target_recipients.err().unwrap());
        return;
    }
    let target_recipients = target_recipients
        .unwrap()
        .into_iter()
        .filter(|r| trusted_keys.contains_key(r))
        .collect::<HashSet<String>>();
    let current_recipients = current_store
        .recipients
        .iter()
        .map(|r| r.device_id.clone())
        .collect::<HashSet<String>>();

    let targ_sub_cur = target_recipients.is_subset(&current_recipients);
    let cur_sub_targ = current_recipients.is_subset(&target_recipients);

    if targ_sub_cur && cur_sub_targ {
        return;
    } else if targ_sub_cur {
        current_store.recipients = current_store
            .recipients
            .into_iter()
            .filter(|r| target_recipients.contains(&r.device_id))
            .collect();
        write_file(path, current_store);
        return;
    }

    to_encrypt.push((path.to_path_buf(), current_store));
    new_recipients.push(target_recipients.into_iter().collect());
}

fn submit_reencryption(
    trusted_keys: &HashMap<String, &PublicKey>,
    to_encrypt: &Vec<(PathBuf, SecretStore)>,
    new_recipients: &Vec<Vec<String>>,
) {
    if to_encrypt.len() != new_recipients.len() {
        panic!("to_encrypt.len() != new_recipients.len()");
    }

    let local_keys: HashSet<String> = private::get_device_keys()
        .into_iter()
        .map(|p| p.device_id)
        .collect();
    let requests = to_encrypt
        .iter()
        .map(|(_, st)| decrypt::build_request(st, trusted_keys, &local_keys))
        .collect();
    let responses = client::batch_decrypt(requests);
    if responses.is_err() {
        eprintln!(
            "Unable to send decrypt requests: {}",
            responses.err().unwrap()
        );
        return;
    }
    let responses = responses.unwrap();
    for i in 0..to_encrypt.len() {
        let (ref this_path, ref this_store) = to_encrypt[i];
        let ref this_recipients = new_recipients[i];
        let ref this_resp = responses[i];
        if this_resp.is_err() {
            eprintln!(
                "Unable to decrypt file {}: {}",
                this_path.to_str().unwrap(),
                this_resp.as_ref().err().unwrap()
            );
            continue;
        }

        let mut this_store = this_store.clone();
        this_store.recipients = this_recipients
            .iter()
            .map(|r| {
                let pkey = trusted_keys.get(r).unwrap();
                let payload = pkey.encrypt(this_resp.as_ref().unwrap());
                super::Recipient {
                    device_id: r.to_string(),
                    encrypted_box: payload,
                }
            })
            .collect();
        let write_res = write_file(&this_path, this_store.clone());
        if write_res.is_err() {
            eprintln!(
                "Unable to write secret store for path {}: {}",
                this_path.to_str().unwrap(),
                write_res.err().unwrap()
            );
        }
    }
}

fn parse_file(path: &Path) -> Result<SecretStore, String> {
    let contents = fs::read_to_string(path).map_err(|e| format!("Unable to read file: {}", e))?;
    let parsed_contents: super::SecretStoreFormat = serde_json::from_str(&contents)
        .map_err(|e| format!("Unable to parse secret store json: {}", e))?;
    parsed_contents
        .into_secret_store()
        .ok_or("invalid base32 encoding".to_string())
}

fn write_file(path: &Path, store: SecretStore) -> Result<(), String> {
    let encoded_store = super::SecretStoreFormat::new(store);
    let json_store = serde_json::to_string(&encoded_store).unwrap();

    fs::write(path, json_store.as_bytes()).map_err(|e| format!("Unable to write to file: {}", e))
}
