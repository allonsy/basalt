use super::public::PublicKey;
use super::state;
use super::vault;
use crate::config;
use std::path::Path;

pub fn path_is_safe(p: &str) -> bool {
    let store_dir = config::get_store_directory();
    let full_path = store_dir.join(p);
    let canon_path = full_path.canonicalize().unwrap_or(full_path);
    canon_path.starts_with(store_dir)
}

pub fn get_key_names_for_path(st: &mut state::State, p: &str) -> Result<Vec<String>, String> {
    let chain = st.get_chain()?;
    let keys = chain.get_keys_for_path(p);
    Ok(keys.iter().map(|k| k.get_key_name().to_string()).collect())
}

pub fn get_all_key_names(st: &mut state::State) -> Result<Vec<String>, String> {
    let chain = st.get_chain()?;
    Ok(chain
        .get_keys()
        .iter()
        .map(|k| k.get_key_name().to_string())
        .collect())
}

fn key_names_equal(names1: &[String], names2: &[String]) -> bool {
    let mut names1_vec = Vec::new();
    names1_vec.extend_from_slice(names1);
    names1_vec.sort();
    let mut names2_vec = Vec::new();
    names2_vec.extend_from_slice(names2);
    names2_vec.sort();

    names1_vec == names2_vec
}

pub fn change_keys_for_path(
    st: &mut state::State,
    path: &str,
    new_keys: Vec<String>,
) -> Result<(), String> {
    let actual_path = config::get_store_directory().join(path);
    if !actual_path.exists() {
        return Err(format!("Path '{}' doesn't exist in the store", path));
    }
    if actual_path.is_file() {
        reencrypt_file(st, path, &new_keys);
    } else if actual_path.is_dir() {
        reencrypt_dir(st, path, &new_keys);
    }

    st.get_chain()?.paths.insert(path.to_string(), new_keys);
    Ok(())
}

pub fn reencrypt_file(
    st: &mut state::State,
    path: &str,
    new_keys: &[String],
) -> Result<(), String> {
    {
        let keychain = st.get_chain()?;
        let old_keys: Vec<String> = keychain
            .get_keys_for_path(path)
            .iter()
            .map(|k| k.get_key_name().to_string())
            .collect();
        if key_names_equal(&old_keys, new_keys) {
            return Ok(());
        }
    }

    let contents = vault::Vault::unlock_vault(st, path)?;
    let keychain = st.get_chain()?;
    let new_recipients = keychain.key_names_to_keys(&new_keys);
    vault::Vault::write_vault(path, &contents, new_recipients)
}

pub fn reencrypt_dir(st: &mut state::State, path: &str, new_keys: &[String]) -> Result<(), String> {
    let full_path = config::get_store_directory().join(path);
    let sub_entries = full_path
        .read_dir()
        .map_err(|e| format!("Unable to read directory: {}", e))?;

    for entry in sub_entries {
        if entry.is_ok() {
            let entry = entry.unwrap().file_name();
            let new_path = Path::new(path).join(&entry);
            let new_full_path = full_path.join(entry);
            if st
                .get_chain()?
                .paths
                .contains_key(new_path.to_str().unwrap())
            {
                continue;
            }
            if new_full_path.is_dir() {
                reencrypt_dir(st, new_path.to_str().unwrap(), new_keys);
            } else if new_full_path.is_file() {
                reencrypt_file(st, new_path.to_str().unwrap(), new_keys);
            }
        }
    }

    Ok(())
}
