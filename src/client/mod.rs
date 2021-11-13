use crate::keys::keyring;
use crate::keys::private::OnDiskPrivateKey;

pub fn decrypt(keyhash: &str, payload: &[u8]) -> Result<Vec<u8>, ()> {
    let priv_key = get_priv_key_by_hash(keyhash)?;

    match priv_key {
        OnDiskPrivateKey::UnencryptedKey(key) => key.decrypt(payload),
        OnDiskPrivateKey::EncryptedKey(_) => {
            unimplemented!("Password decryption not yet supported")
        }
    }
}

pub fn sign(keyhash: &str, payload: &[u8]) -> Result<Vec<u8>, ()> {
    let priv_key = get_priv_key_by_hash(keyhash)?;

    match priv_key {
        OnDiskPrivateKey::UnencryptedKey(key) => Ok(key.sign(payload)),
        OnDiskPrivateKey::EncryptedKey(_) => {
            unimplemented!("Password decryption not yet supported")
        }
    }
}

pub fn get_priv_key_by_hash(keyhash: &str) -> Result<OnDiskPrivateKey, ()> {
    let priv_keys = keyring::get_device_keys();

    for priv_key in priv_keys {
        if priv_key.hash() == keyhash {
            return Ok(priv_key);
        }
    }

    Err(())
}
