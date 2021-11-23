use crate::config;
use crate::keys::private::OnDiskPrivateKey;
use glob::glob;

pub fn get_device_keys() -> Vec<OnDiskPrivateKey> {
    let mut priv_key_dir = config::get_private_key_dir();
    priv_key_dir.push("*.priv");

    let mut priv_keys = Vec::new();

    let glob_matches = glob(priv_key_dir.to_str().unwrap());
    if let Err(e) = glob_matches {
        eprintln!("Unable to read private key directory: {}", e);
        return priv_keys;
    }

    let glob_matches = glob_matches.unwrap();

    for entry in glob_matches {
        match entry {
            Ok(file_path) => {
                let parsed_priv_key = OnDiskPrivateKey::read_key(&file_path);
                match parsed_priv_key {
                    Ok(key) => priv_keys.push(key),
                    Err(e) => eprintln!("Unable to read private key: {}", e),
                };
            }
            Err(e) => eprintln!("Unable to read private key: {}", e),
        }
    }

    priv_keys
}

pub fn decrypt(keyhash: &str, payload: &[u8]) -> Result<Vec<u8>, ()> {
    let priv_key = get_priv_key_by_hash(keyhash)?;

    match priv_key {
        OnDiskPrivateKey::UnencryptedKey(key) => key.decrypt(payload),
        OnDiskPrivateKey::EncryptedKey(_) => {
            unimplemented!("Password decryption not yet supported")
        }
    }
}

pub fn sign_with_key(priv_key: &OnDiskPrivateKey, payload: &[u8]) -> Result<Vec<u8>, ()> {
    match priv_key {
        OnDiskPrivateKey::UnencryptedKey(key) => Ok(key.sign(payload)),
        OnDiskPrivateKey::EncryptedKey(_) => {
            unimplemented!("Password decryption not yet supported")
        }
    }
}

pub fn sign(payload: &[u8]) -> Result<(Vec<u8>, String), ()> {
    let default_key = get_default_key()?;
    let payload = sign_with_key(&default_key, payload)?;
    Ok((payload, default_key.hash()))
}

pub fn get_default_key() -> Result<OnDiskPrivateKey, ()> {
    let mut keys = get_device_keys();
    if keys.is_empty() {
        Err(())
    } else {
        Ok(keys.pop().unwrap())
    }
}

pub fn get_priv_key_by_hash(keyhash: &str) -> Result<OnDiskPrivateKey, ()> {
    let priv_keys = get_device_keys();

    for priv_key in priv_keys {
        if priv_key.hash() == keyhash {
            return Ok(priv_key);
        }
    }

    Err(())
}
