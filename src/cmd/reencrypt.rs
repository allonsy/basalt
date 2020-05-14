use crate::config;
use crate::secret::reencrypt::reencrypt_path;

pub fn reencrypt(path: Option<&str>) {
    if path.is_none() {
        reencrypt_path(config::get_store_dir().to_str().unwrap());
    } else {
        reencrypt_path(path.unwrap());
    }
}
