use super::private::OnDiskPrivateKey;
use super::public;
use crate::config;
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
