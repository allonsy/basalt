use std::collections::HashMap;
use url::Url;

pub struct Vault {
    items: HashMap<String, VaultItem>,
    folders: HashMap<String, Vault>,
}

pub struct VaultItem {
    name: String,
    username: String,
    password: String,
    item_type: String,
    url: Url,
    additional_fields: HashMap<String, String>,
}

pub trait OnDiskVault {
    fn version_number(&self) -> u32;
    fn from_bytes(bytes: &[u8], passphrase: Option<&[u8]>) -> Result<Vault, String>;
    fn to_bytes(vault: &Vault) -> Result<(), String>;
}
