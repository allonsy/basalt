use crate::keys::KeySignature;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::SodiumPrivateKey;
use crate::keys::SodiumPublicKey;
use crate::util;
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
    json: &[u8],
    pwd: Option<&str>,
) -> Result<Box<dyn PrivateKey + Send>, ParseError> {
    let json_str = std::str::from_utf8(json)
        .map_err(|_| ParseError::JsonError("JSON isn't UTF8".to_string()))?;
    let private_key_wrapper: super::PrivateKeyWrapperFormat =
        serde_json::from_str(json_str).map_err(|e| ParseError::JsonError(format!("{}", e)))?;
    let device_id = private_key_wrapper.device_id.clone();
    let sec_key = match private_key_wrapper.key {
        super::PrivateKeyFormat::PrivateSodiumKey(sodiumkey) => match sodiumkey {
            super::PrivateSodiumKeyFormat::Encrypted(locked_key) => {
                if pwd.is_none() {
                    return Err(ParseError::MissingPassword);
                }
                let pwd = pwd.unwrap();
                let enc_key = decrypt_secret_key(
                    &locked_key.encrypt_key,
                    &locked_key.encrypt_salt,
                    &locked_key.encrypt_nonce,
                    pwd,
                )?;
                let sign_key = decrypt_secret_key(
                    &locked_key.sign_key,
                    &locked_key.sign_salt,
                    &locked_key.sign_nonce,
                    pwd,
                )?;
                let sodium_enc_key =
                    box_::SecretKey::from_slice(&enc_key).ok_or(ParseError::MalformedKeyError)?;
                let sodium_sign_key =
                    sign::SecretKey::from_slice(&sign_key).ok_or(ParseError::MalformedKeyError)?;
                SodiumPrivateKey::new(device_id, sodium_enc_key, sodium_sign_key)
            }
            super::PrivateSodiumKeyFormat::Unencrypted(unlocked_key) => {
                let enc_key = base32_decode(&unlocked_key.encrypt_key)?;
                let sign_key = base32_decode(&unlocked_key.sign_key)?;
                let sodium_enc_key =
                    box_::SecretKey::from_slice(&enc_key).ok_or(ParseError::MalformedKeyError)?;
                let sodium_sign_key =
                    sign::SecretKey::from_slice(&sign_key).ok_or(ParseError::MalformedKeyError)?;
                SodiumPrivateKey::new(device_id, sodium_enc_key, sodium_sign_key)
            }
        },
    };
    Ok(Box::new(sec_key))
}

pub fn parse_public_key_json(pub_key_bytes: &[u8]) -> Result<Box<dyn PublicKey>, ParseError> {
    let pub_key_str = std::str::from_utf8(pub_key_bytes)
        .map_err(|e| ParseError::JsonError("JSON isn't utf8".to_string()))?;
    let pub_key_format: super::PublicKeyWrapperFormat =
        serde_json::from_str(pub_key_str).map_err(|e| ParseError::JsonError(format!("{}", e)))?;
    let device_id = pub_key_format.device_id.clone();
    let signatures = pub_key_format
        .signatures
        .iter()
        .map(|s| {
            Ok(KeySignature {
                public_key_id: device_id.clone(),
                signing_key_id: s.signing_key_id.clone(),
                signature: base32_decode(&s.signature)?,
            })
        })
        .collect::<Result<Vec<KeySignature>, ParseError>>()?;
    match pub_key_format.key {
        super::PublicKeyFormat::PublicSodiumKey(key) => {
            let enc_key = base32_decode(&key.encrypt_key)?;
            let sign_key = base32_decode(&key.sign_key)?;
            let sodium_enc_key =
                box_::PublicKey::from_slice(&enc_key).ok_or(ParseError::MalformedKeyError)?;
            let sodium_sign_key =
                sign::PublicKey::from_slice(&sign_key).ok_or(ParseError::MalformedKeyError)?;
            Ok(Box::new(SodiumPublicKey::new(
                device_id,
                sodium_enc_key,
                sodium_sign_key,
                signatures,
            )))
        }
    }
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
