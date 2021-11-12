mod keyring;
mod private;
mod public;
use crate::config;
use crate::menu;

pub fn gen_sodium_key() {
    let priv_keys = keyring::get_device_keys();
    println!("num keys: {}", priv_keys.len());
}
