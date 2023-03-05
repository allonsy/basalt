use super::super::vault::OnDiskVault;
use std::collections::HashMap;
use url::Url;

pub struct V1Vault {
    items: HashMap<String, VaultItem>,
    folders: HashMap<String, V1Vault>,
}

pub struct VaultItem {
    name: String,
    username: String,
    password: String,
    item_type: String,
    url: Url,
    additional_fields: HashMap<String, String>,
}

impl OnDiskVault for V1Vault {
    fn version_number(&self) -> u32 {
        1
    }

    fn from_bytes(
        bytes: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<crate::daemon::vault::Vault, String> {
        Err("Not Implemented".to_string())
    }

    fn to_bytes(vault: &crate::daemon::vault::Vault) -> Result<(), String> {
        Err("Not implemented".to_string())
    }
}
