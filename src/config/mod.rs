use crate::constants;
use dirs;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

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

fn init(app_dir: &Path) {
    if app_dir.is_dir() {
        return;
    }
    fs::create_dir_all(app_dir).unwrap();
}
