use crate::constants;
use dirs;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

pub const DEVICE_ID_FILE_NAME: &'static str = ".device_ids";

pub fn get_app_dir() -> PathBuf {
    let home_dir = dirs::home_dir().unwrap();
    let app_dir = home_dir.join(format!(".{}", constants::APP_NAME));
    init(&app_dir);
    app_dir
}

pub fn get_keys_dir() -> PathBuf {
    let app_dir = get_app_dir();
    let keys_dir = app_dir.join("keys");
    init(&keys_dir);
    keys_dir
}

pub fn get_store_dir() -> PathBuf {
    let app_dir = get_app_dir();
    let store_dir = app_dir.join("store");
    init(&store_dir);
    store_dir
}

pub fn get_password_dir() -> PathBuf {
    let store_dir = get_store_dir();
    let pass_dir = store_dir.join("passwords");
    init(&pass_dir);
    pass_dir
}

pub fn get_pubkey_dir() -> PathBuf {
    let store_dir = get_pubkey_dir();
    let pubkey_dir = store_dir.join(".keys");
    init(&pubkey_dir);
    pubkey_dir
}

pub fn get_chain_head_file() -> PathBuf {
    let keys_dir = get_keys_dir();
    keys_dir.join("chain.head")
}

fn init(app_dir: &Path) {
    if app_dir.is_dir() {
        return;
    }
    fs::create_dir_all(app_dir).unwrap();
}
