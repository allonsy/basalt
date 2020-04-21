use super::PublicKey;
use crate::config;
use crate::parse::deserialize;
use glob::glob;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;

pub fn load_keys_for_file(path: &Path) -> Result<Vec<Box<dyn PublicKey>>, String> {
    let device_ids = get_device_ids(path)?;
    let mut keys = load_public_keys();

    let mut pub_keys = Vec::new();
    for device_id in device_ids {
        let key = keys.remove(&device_id);
        if key.is_none() {
            eprintln!("WARNING: Unable to find key for device id: {}", device_id);
        } else {
            pub_keys.push(key.unwrap());
        }
    }
    Ok(pub_keys)
}

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

    for (device_id, key) in untrusted_keys.iter() {
        for sig in key.get_signatures() {
            if trusted_keys.contains_key(&sig.signing_key_id) {
                let signing_key = trusted_keys.get(&sig.signing_key_id).unwrap();
                if sig.verify_signature(key.as_ref(), signing_key.as_ref()) {
                    new_trusted.push(device_id.clone())
                }
            }
        }
    }

    for device_id in new_trusted {
        let pub_key = untrusted_keys.remove(&device_id).unwrap();
        sign_key(pub_key.as_ref());
        trusted_keys.insert(device_id.to_string(), pub_key);
        changed = true;
    }
    changed
}

fn get_device_ids(path: &Path) -> Result<Vec<String>, String> {
    let top_dir = config::get_store_dir();
    let mut device_id_file = top_dir.join(config::DEVICE_ID_FILE_NAME);
    loop {
        let this_file = path.parent().ok_or("No parent found for device file")?;
        let this_file = this_file.join(config::DEVICE_ID_FILE_NAME);
        if this_file.is_file() {
            device_id_file = this_file;
            break;
        }
        if this_file == device_id_file {
            break;
        }
    }

    let id_file =
        File::open(device_id_file).map_err(|e| format!("Unable to open device id file: {}", e))?;
    let mut bufreader = BufReader::new(id_file);

    let mut device_ids = Vec::new();
    let mut id_line = String::new();
    while bufreader
        .read_line(&mut id_line)
        .map_err(|e| format!("Unable to read line from file: {}", e))?
        != 0
    {
        device_ids.push(id_line.trim().to_string());
    }

    Ok(device_ids)
}

fn sign_key(pub_key: &dyn PublicKey) {}

fn get_device_keys() -> HashMap<String, Box<dyn PublicKey>> {
    let keys_dir = config::get_keys_dir();
    let pattern = keys_dir.join("*.pub");

    let mut keys = HashMap::new();

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
    let mut keyfile = File::open(path).map_err(|e| format!("Unable to open file: {}", e))?;
    let mut file_bytes = Vec::new();

    keyfile
        .read_to_end(&mut file_bytes)
        .map_err(|e| format!("Unable to read file: {}", e))?;
    deserialize::parse_public_key_json(&file_bytes)
        .map_err(|e| format!("Unable to parse public key"))
}
