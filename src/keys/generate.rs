use crate::agent::pinentry;
use crate::config;
use crate::keys::sodium;
use crate::parse::serialize;
use crate::util::prompt_user;
use crate::util::user_menu;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn generate_key() {
    let device_id = prompt_user("Please enter a device name");
    let key_type_choices = vec!["sodium"];
    let key_type_choice = user_menu("Please choose a key type", &key_type_choices, Some(0));
    match key_type_choices[key_type_choice] {
        "sodium" => generate_sodium_key(&device_id),
        _ => panic!("Unknown user choice"),
    }
}

fn generate_sodium_key(device_id: &str) {
    let pin = pinentry::generate_pin(device_id);
    if pin.is_err() {
        println!("Invalid PIN, discarding key");
        return;
    }
    let pin = pin.unwrap();
    let pin_opt = if pin.is_empty() {
        None
    } else {
        Some(pin.as_str())
    };
    let sec_key = sodium::SodiumPrivateKey::generate(device_id.to_string());
    let pub_key = sodium::SodiumPublicKey::new(
        device_id.to_string(),
        sec_key.get_enc_key().public_key(),
        sec_key.get_sign_key().public_key(),
        Vec::new(),
    );

    let sec_key_bytes = serialize::serialize_sodium_private_key(&sec_key, pin_opt);
    if sec_key_bytes.is_none() {
        println!("Unable to encrypt secret key, aborting...");
        return;
    }
    let pub_key_bytes = serialize::serialize_sodium_pub_key(&pub_key);

    let base_dir = config::get_app_dir().join("keys");
    let sec_key_file = base_dir.join(format!("{}.sec", device_id));
    let pub_key_file = base_dir.join(format!("{}.pub", device_id));
    write_key(&sec_key_file, &sec_key_bytes.unwrap());
    write_key(&pub_key_file, &pub_key_bytes);
}

fn write_key(file_name: &Path, payload: &[u8]) {
    if file_name.exists() {
        println!("Key with that device name already exists, aborting...");
        return;
    }
    let file = File::create(file_name);
    if file.is_err() {
        println!("Unable to create new key file: {}", file.err().unwrap());
        return;
    }
    let mut file = file.unwrap();
    let write_res = file.write_all(payload);
    if write_res.is_err() {
        println!("Unable to write key to file: {}", write_res.err().unwrap());
        return;
    }
}
