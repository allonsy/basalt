use crate::keys::KeySignature;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::SodiumPrivateKey;
use crate::keys::SodiumPublicKey;
use crate::util;
use serde_json::Map;
use serde_json::Value;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::pwhash::Salt;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::sign;

#[derive(Debug)]
pub enum ParseError {
    JsonError(String),
    Base32DecodeError,
    MalformedKeyError,
    MalformedSaltError,
    DecryptError,
    MissingPassword,
}

pub fn parse_private_key_json(
    json: Value,
    pwd: Option<&str>,
) -> Result<Box<dyn PrivateKey>, ParseError> {
    let map = json.as_object();
    if map.is_none() {
        return Err(ParseError::JsonError(
            "private key must be an object".to_string(),
        ));
    }
    let map = map.unwrap();
    let key_type = assert_obj_string(map, super::KEY_TYPE_NAME)?;
    let device_id = assert_obj_string(map, super::DEVICE_ID_NAME)?;

    match key_type {
        super::KEY_TYPE_SODIUM => {
            let sodium_key_map = assert_obj_map(map, super::KEY_NAME)?;
            parse_sodium_private_key(device_id, sodium_key_map, pwd)
        }
        _ => Err(ParseError::JsonError(format!(
            "Unknown key type: {}",
            key_type
        ))),
    }
}

pub fn parse_public_key_json(json: Value) -> Result<Box<dyn PublicKey>, ParseError> {
    match json {
        Value::Object(map) => parse_public_key_map(&map),
        _ => Err(ParseError::JsonError("JSON isn't an object".to_string())),
    }
}

fn parse_public_key_map(map: &Map<String, Value>) -> Result<Box<dyn PublicKey>, ParseError> {
    let key_type = assert_obj_string(map, super::KEY_TYPE_NAME)?;
    let device_id = assert_obj_string(map, super::DEVICE_ID_NAME)?;
    let signatures = assert_obj_array(map, super::SIGNATURES_NAME)?;
    let parsed_signatures = parse_signatures(device_id, signatures)?;
    match key_type {
        super::KEY_TYPE_SODIUM => {
            let sodium_key_map = assert_obj_map(map, super::KEY_NAME)?;
            parse_sodium_pub_key(device_id, parsed_signatures, sodium_key_map)
        }
        _ => Err(ParseError::JsonError(format!(
            "unknown key type: {}",
            key_type
        ))),
    }
}

fn parse_sodium_pub_key(
    device_id: &str,
    signatures: Vec<KeySignature>,
    map: &Map<String, Value>,
) -> Result<Box<dyn PublicKey>, ParseError> {
    let enc_key = assert_obj_string(map, super::ENCRYPT_KEY_NAME)?;
    let enc_key_bytes = base32_decode(enc_key)?;
    let parsed_enc_key = box_::PublicKey::from_slice(&enc_key_bytes);
    if parsed_enc_key.is_none() {
        return Err(ParseError::MalformedKeyError);
    }
    let parsed_enc_key = parsed_enc_key.unwrap();

    let sign_key = assert_obj_string(map, super::SIGNING_KEY_NAME)?;
    let sign_key_bytes = base32_decode(sign_key)?;
    let parsed_sign_key = sign::PublicKey::from_slice(&sign_key_bytes);
    if parsed_sign_key.is_none() {
        return Err(ParseError::MalformedKeyError);
    }
    let parsed_sign_key = parsed_sign_key.unwrap();

    Ok(Box::new(SodiumPublicKey::new(
        device_id.to_string(),
        parsed_enc_key,
        parsed_sign_key,
        signatures,
    )))
}

fn parse_signatures(device_id: &str, sigs: &Vec<Value>) -> Result<Vec<KeySignature>, ParseError> {
    let mut signatures = Vec::new();
    for sig in sigs {
        let sig_obj = sig.as_object();
        if sig_obj.is_none() {
            return Err(ParseError::JsonError(
                "Signature isn't a json object".to_string(),
            ));
        }
        let sig_obj = sig_obj.unwrap();
        let signing_id = assert_obj_string(&sig_obj, super::SIGNATURE_SIGNING_KEY_NAME)?;
        let signature = assert_obj_string(&sig_obj, super::SIGNATURE_NAME)?;
        let signature_bytes = base32_decode(signature)?;
        signatures.push(KeySignature::new(
            device_id.to_string(),
            signing_id.to_string(),
            signature_bytes,
        ));
    }
    Ok(signatures)
}

fn parse_sodium_private_key(
    device_id: &str,
    map: &Map<String, Value>,
    pwd: Option<&str>,
) -> Result<Box<dyn PrivateKey>, ParseError> {
    let enc_key = if map.contains_key(super::ENCRYPTION_KEY_SALT_NAME) {
        if pwd.is_none() {
            return Err(ParseError::MissingPassword);
        }
        let enc_key_salt = assert_obj_string(map, super::ENCRYPTION_KEY_SALT_NAME)?;
        let enc_key_nonce = assert_obj_string(map, super::ENCRYPT_KEY_NONCE_NAME)?;
        let enc_key = assert_obj_string(map, super::ENCRYPT_KEY_NAME)?;
        decrypt_secret_key(enc_key, enc_key_salt, enc_key_nonce, pwd.unwrap())?
    } else {
        base32_decode(assert_obj_string(map, super::ENCRYPT_KEY_NAME)?)?
    };
    let enc_key = box_::SecretKey::from_slice(&enc_key);
    if enc_key.is_none() {
        return Err(ParseError::MalformedKeyError);
    }

    let sign_key = if map.contains_key(super::SIGNINING_KEY_SALT_NAME) {
        if pwd.is_none() {
            return Err(ParseError::MissingPassword);
        }
        let sign_key_salt = assert_obj_string(map, super::SIGNINING_KEY_SALT_NAME)?;
        let sign_key_nonce = assert_obj_string(map, super::SIGNINING_KEY_NONCE_NAME)?;
        let sign_key = assert_obj_string(map, super::SIGNING_KEY_NAME)?;
        decrypt_secret_key(sign_key, sign_key_salt, sign_key_nonce, pwd.unwrap())?
    } else {
        base32_decode(assert_obj_string(map, super::SIGNING_KEY_NAME)?)?
    };

    let sign_key = sign::SecretKey::from_slice(&sign_key);
    if sign_key.is_none() {
        return Err(ParseError::MalformedKeyError);
    }

    Ok(Box::new(SodiumPrivateKey::new(
        device_id.to_string(),
        enc_key.unwrap(),
        sign_key.unwrap(),
    )))
}

fn base32_decode(val: &str) -> Result<Vec<u8>, ParseError> {
    let decoded = util::base32_decode(val);
    if decoded.is_none() {
        Err(ParseError::Base32DecodeError)
    } else {
        Ok(decoded.unwrap())
    }
}

fn decrypt_secret_key(
    string_key: &str,
    string_salt: &str,
    string_nonce: &str,
    string_pwd: &str,
) -> Result<Vec<u8>, ParseError> {
    let key = base32_decode(string_key)?;
    let pwd = string_pwd.as_bytes();
    let salt = base32_decode(string_salt)?;
    let salt = Salt::from_slice(&salt);
    if salt.is_none() {
        return Err(ParseError::MalformedSaltError);
    }
    let salt = salt.unwrap();
    let nonce = base32_decode(string_nonce)?;
    let nonce = secretbox::Nonce::from_slice(&nonce);
    if nonce.is_none() {
        return Err(ParseError::MalformedSaltError);
    }
    let nonce = nonce.unwrap();

    let mut decrypt_key = [0; secretbox::KEYBYTES];
    let decrypt_key_res = pwhash::derive_key_interactive(&mut decrypt_key, &pwd, &salt);
    if decrypt_key_res.is_err() {
        return Err(ParseError::DecryptError);
    }

    let symmetric_key = secretbox::Key::from_slice(&decrypt_key).unwrap();
    let decrypted_key = secretbox::open(&key, &nonce, &symmetric_key);
    if decrypted_key.is_err() {
        return Err(ParseError::DecryptError);
    }
    Ok(decrypted_key.unwrap())
}

fn assert_obj_string<'a>(
    val: &'a Map<String, Value>,
    key_name: &str,
) -> Result<&'a str, ParseError> {
    let string_val = val.get(key_name);
    if string_val.is_none() {
        return Err(ParseError::JsonError(format!(
            "Unable to find required key: {}",
            key_name
        )));
    }
    let string_val = string_val.unwrap();
    let string_coerced = string_val.as_str();
    if string_coerced.is_none() {
        return Err(ParseError::JsonError(format!(
            "key: '{}' isn't a string",
            key_name
        )));
    }
    Ok(string_coerced.unwrap())
}

fn assert_obj_map<'a>(
    val: &'a Map<String, Value>,
    key_name: &str,
) -> Result<&'a Map<String, Value>, ParseError> {
    let obj_val = val.get(key_name);
    if obj_val.is_none() {
        return Err(ParseError::JsonError(format!(
            "Unable to find required key: {}",
            key_name
        )));
    }

    let obj_val = obj_val.unwrap().as_object();
    if obj_val.is_none() {
        return Err(ParseError::JsonError(format!(
            "key '{}' isn't an object",
            key_name
        )));
    }
    Ok(obj_val.unwrap())
}

fn assert_obj_array<'a>(
    map: &'a Map<String, Value>,
    key_name: &str,
) -> Result<&'a Vec<Value>, ParseError> {
    let array_val = map.get(key_name);
    if array_val.is_none() {
        return Err(ParseError::JsonError(format!(
            "Unable to find required key: {}",
            key_name
        )));
    }
    let array_val = array_val.unwrap().as_array();
    if array_val.is_none() {
        return Err(ParseError::JsonError(format!(
            "key '{}' isn't an array",
            key_name
        )));
    }
    Ok(array_val.unwrap())
}
