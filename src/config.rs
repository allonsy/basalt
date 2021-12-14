use std::path::PathBuf;

pub const KEY_ID_FILE_NAME: &'static str = ".key_ids";

fn create_dir_if_needed(path: PathBuf) -> PathBuf {
    if !path.exists() {
        std::fs::create_dir_all(&path).unwrap();
    }
    path
}

pub fn get_app_dir() -> PathBuf {
    create_dir_if_needed(PathBuf::from("/home/alecsnyder/.basalt"))
}

pub fn get_store_dir() -> PathBuf {
    let mut app_dir = get_app_dir();
    app_dir.push("store");
    create_dir_if_needed(app_dir)
}

pub fn get_private_key_dir() -> PathBuf {
    let mut app_dir = get_app_dir();
    app_dir.push("keys");
    create_dir_if_needed(app_dir)
}

pub fn get_public_keys_dir() -> PathBuf {
    let mut store_dir = get_store_dir();
    store_dir.push(".keys");
    create_dir_if_needed(store_dir)
}

pub fn get_agent_socket_path() -> PathBuf {
    let app_dir = get_app_dir();
    app_dir.join("agent.socket")
}
