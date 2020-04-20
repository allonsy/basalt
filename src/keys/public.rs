use super::PublicKey;
use crate::config;
use crate::parse::deserialize;
use glob::glob;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn load_public_keys() -> HashMap<String, Box<dyn PublicKey>> {
    let mut trusted_keys = get_device_keys();
    let mut untrusted_keys = HashMap::new();

    let pubkey_dir = config::get_pubkey_dir();
    let pattern = pubkey_dir.join("*.pub");
    let matches = glob(pattern.to_str().unwrap());
    if matches.is_err() {
        eprintln!("Unable to parse glob: {}", matches.err().unwrap());
        return trusted_keys;
    }
    let matches = matches.unwrap();
    for keyfile in matches {
        if keyfile.is_err() {
            eprintln!("Unable to find file: {}", keyfile.err().unwrap());
            continue;
        }
        let keyfile = keyfile.unwrap();
        let pubkey = read_public_key(&keyfile);
        if pubkey.is_err() {
            eprintln!("{}", pubkey.err().unwrap());
            continue;
        }
        let pubkey = pubkey.unwrap();
        if trusted_keys.contains_key(pubkey.get_device_id()) {
            continue;
        }
        untrusted_keys.insert(pubkey.get_device_id().to_string(), pubkey);
    }

    loop {
        let changed = get_new_trusted_keys(&mut trusted_keys, &mut untrusted_keys);
        if untrusted_keys.is_empty() {
            break;
        }
        if !changed {
            break;
        }
    }

    trusted_keys
}

fn get_new_trusted_keys(
    trusted_keys: &mut HashMap<String, Box<dyn PublicKey>>,
    untrusted_keys: &mut HashMap<String, Box<dyn PublicKey>>,
) -> bool {
    let mut changed = false;
    let mut new_trusted = Vec::new();

    for (device_id, key) in untrusted_keys {
        for sig in key.get_signatures() {
            if trusted_keys.contains_key(&sig.signing_key_id) {
                let signing_key = trusted_keys.get(&sig.signing_key_id).unwrap();
                if sig.verify_signature(key.as_ref(), signing_key.as_ref()) {
                    new_trusted.push(device_id)
                }
            }
        }
    }

    for device_id in new_trusted {
        let pub_key = untrusted_keys.remove(device_id).unwrap();
        sign_key(pub_key.as_ref());
        trusted_keys.insert(device_id.to_string(), pub_key);
        changed = true;
    }
    changed
}

fn sign_key(pub_key: &dyn PublicKey) {}

fn get_device_keys() -> HashMap<String, Box<dyn PublicKey>> {
    let keys_dir = config::get_keys_dir();
    let pattern = keys_dir.join("*.pub");

    let keys = HashMap::new();

    let matches = glob(pattern.to_str().unwrap());
    if matches.is_err() {
        eprintln!("Unable to parse glob: {}", matches.err().unwrap());
        return keys;
    }
    let matches = matches.unwrap();
    for keyfile in matches {
        if keyfile.is_err() {
            eprintln!("Unable to find keyfile: {}", keyfile.err().unwrap());
        } else {
            let keyfile = keyfile.unwrap();
            let pubkey = read_public_key(&keyfile);
            if pubkey.is_err() {
                eprintln!("{}", pubkey.err().unwrap());
            } else {
                let pubkey = pubkey.unwrap();
                keys.insert(pubkey.get_device_id().to_string(), pubkey);
            }
        }
    }
    keys
}

fn read_public_key(path: &Path) -> Result<Box<dyn PublicKey>, String> {
    let keyfile = File::open(path).map_err(|e| format!("Unable to open file: {}", e))?;
    let mut file_bytes = Vec::new();

    keyfile
        .read_to_end(&mut file_bytes)
        .map_err(|e| format!("Unable to read file: {}", e))?;
    deserialize::parse_public_key_json(&file_bytes)
        .map_err(|e| format!("Unable to parse public key"))
}
