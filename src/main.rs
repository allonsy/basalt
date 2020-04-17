mod agent;
mod config;
mod constants;
mod keys;
mod parse;
mod secret;
mod util;

use keys::PrivateKey;
use keys::PublicKey;
use parse::deserialize::ParseError;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;

const PRIVATE_KEY_FILENAME: &'static str = "secret_key.json";
const PUBLIC_KEY_FILENAME: &'static str = "public_key.json";

fn main() {
    let (pubkey, _) = get_keys();
    println!("Read key for device: '{}'", pubkey.get_device_id());
}

fn get_keys() -> (Box<dyn PublicKey>, Box<dyn PrivateKey>) {
    let app_dir = config::get_app_dir();
    let private_key_file = app_dir.join(PRIVATE_KEY_FILENAME);
    let public_key_file = app_dir.join(PUBLIC_KEY_FILENAME);
    if private_key_file.is_file() {
        let sec_key = read_private_key(&private_key_file);
        let pub_key = read_public_key(&public_key_file);
        return (pub_key, sec_key);
    } else {
        println!("No secret key detected");
        let device_id = util::prompt_user("Please enter a device name");
        let password = util::prompt_user("Please enter a password");
        let password_opt = if password.is_empty() {
            None
        } else {
            Some(password.as_str())
        };
        let (pub_key, sec_key) = keys::sodium::generate_new_sodium_key(&device_id);
        let pub_key_json = parse::serialize::serialize_sodium_pub_key(&pub_key);
        let sec_key_json =
            parse::serialize::serialize_sodium_private_key(&sec_key, password_opt).unwrap();
        write_json(&pub_key_json, &public_key_file);
        write_json(&sec_key_json, &private_key_file);
        return (Box::new(pub_key), Box::new(sec_key));
    }
}

fn read_private_key(path: &Path) -> Box<dyn PrivateKey> {
    let json = read_json_file(path);
    let sec_key = parse::deserialize::parse_private_key_json(&json, None);
    match sec_key {
        Ok(k) => k,
        Err(ParseError::MissingPassword) => {
            let pwd = util::prompt_user("Please enter a password for the key");
            parse::deserialize::parse_private_key_json(&json, Some(pwd.as_str())).unwrap()
        }
        _ => sec_key.unwrap(),
    }
}

fn read_public_key(path: &Path) -> Box<dyn PublicKey> {
    let json = read_json_file(path);
    parse::deserialize::parse_public_key_json(&json).unwrap()
}

fn read_json_file(path: &Path) -> Vec<u8> {
    let mut file = File::open(path).unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    contents
}

fn write_json(val: &[u8], filename: &Path) {
    let mut file = File::create(filename).unwrap();
    file.write_all(val).unwrap();
}
