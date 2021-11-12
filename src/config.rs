use std::path::PathBuf;

pub fn get_app_dir() -> PathBuf {
    PathBuf::from("/home/alecsnyder/.basalt")
}

pub fn get_store_dir() -> PathBuf {
    let mut app_dir = get_app_dir();
    app_dir.push("store");
    app_dir
}

pub fn get_private_key_dir() -> PathBuf {
    let mut app_dir = get_app_dir();
    app_dir.push("keys");
    app_dir
}

pub fn get_public_keys_dir() -> PathBuf {
    let mut store_dir = get_store_dir();
    store_dir.push(".keys");
    store_dir
}
