pub mod keyring;
pub mod private;
pub mod public;
use crate::agent;
use crate::client;
use crate::config;
use crate::menu;

pub fn gen_sodium_key() {
    let priv_keys = agent::get_device_keys();
    println!("num keys: {}", priv_keys.len());
}
