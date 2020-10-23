use super::state;
use super::vault;

pub fn read_secret(st: &mut state::State, path: &str) -> Result<Vec<u8>, String> {
    vault::Vault::unlock_vault(st, path)
}

pub fn write_secret(st: &mut state::State, path: &str, payload: Vec<u8>) -> Result<(), String> {
    let chain = st.get_chain()?;
    let keys = chain.get_keys_for_path(path);
    vault::Vault::write_vault(path, &payload, keys)
}
