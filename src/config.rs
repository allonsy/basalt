use crate::constants;
use dirs;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

pub fn get_app_dir() -> PathBuf {
    let home_dir = dirs::home_dir();
    if home_dir.is_none() {
        eprintln!("Unable to retrieve home directory");
        std::process::exit(1);
    }
    let home_dir = home_dir.unwrap();
    let app_dir = home_dir.join(constants::APP_DIR_NAME);
    create_dir(&app_dir);
    app_dir
}

pub fn get_agent_socket_file() -> PathBuf {
    let app_dir = get_app_dir();
    app_dir.join(constants::SOCKET_NAME)
}

pub fn get_store_directory() -> PathBuf {
    let app_dir = get_app_dir();
    let store_dir = app_dir.join(constants::STORE_DIR_NAME);
    create_dir(&store_dir);
    store_dir
}

pub fn get_keys_directory() -> PathBuf {
    let store_dir = get_store_directory();
    let keys_dir = store_dir.join(constants::KEY_DIR_NAME);
    create_dir(&keys_dir);
    keys_dir
}

pub fn create_dir(path: &Path) {
    let res = fs::create_dir_all(path);
    if res.is_err() {
        eprintln!(
            "Unable to create config directory {} with err: {}",
            path.display(),
            res.err().unwrap()
        );
        std::process::exit(1);
    }
}
