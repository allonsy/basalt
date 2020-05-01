use crate::config;
use crate::keys::private;
use crate::keys::public;
use crate::keys::public::KeyChain;
use std::fs;

pub fn init() {
    let keychain = KeyChain::get_keychain();
    if keychain.is_ok() {
        eprintln!("Secret store already initialized");
        std::process::exit(1);
    }

    let mut new_keychain = KeyChain::new();
    private::generate_key(&mut new_keychain);
    let write_res = new_keychain.write_keychain();
    if write_res.is_err() {
        std::process::exit(1);
    }
    match new_keychain.chain[0].event {
        public::KeyEvent::NewKey(pkey) => {
            let device_id_file = config::get_store_dir().join(config::DEVICE_ID_FILE_NAME);
            let write_res = fs::write(device_id_file, format!("{}\n", pkey.device_id));
            if write_res.is_err() {
                eprintln!(
                    "Unable to add device id to root {} file",
                    config::DEVICE_ID_FILE_NAME
                );
                std::process::exit(1);
            }
        }
        _ => {}
    }
}
