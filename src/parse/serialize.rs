use crate::keys::KeySignature;
use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::SodiumPrivateKey;
use crate::keys::SodiumPublicKey;
use crate::util::base32_encode;
use serde_json::json;
use serde_json::Value;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::pwhash::Salt;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::Nonce;

pub fn serialize_sodium_pub_key(key: &SodiumPublicKey) -> Value {
    let enc_key = base32_encode(&key.get_enc_key().0);
    let sign_key = base32_encode(&key.get_sign_key().0);
    let key_payload = json!({
        super::ENCRYPT_KEY_NAME: enc_key,
        super::SIGNING_KEY_NAME: sign_key,
    });
    serialize_public_key(super::KEY_TYPE_SODIUM, key, key_payload)
}

pub fn serialize_sodium_private_key(
    key: &SodiumPrivateKey,
    pwd: Option<&str>,
) -> Result<Value, ()> {
    if pwd.is_some() {
        let pwd = pwd.unwrap();
        let enc_salt = pwhash::gen_salt();
        let enc_nonce = secretbox::gen_nonce();
        let enc_key = encrypt_key(&key.get_enc_key().0, pwd.as_bytes(), &enc_salt, &enc_nonce)?;

        let sign_salt = pwhash::gen_salt();
        let sign_nonce = secretbox::gen_nonce();
        let sign_key = encrypt_key(
            &key.get_sign_key().0,
            pwd.as_bytes(),
            &sign_salt,
            &sign_nonce,
        )?;
        let payload = json!({
            super::ENCRYPTION_KEY_SALT_NAME: base32_encode(&enc_salt.0),
            super::ENCRYPT_KEY_NONCE_NAME: base32_encode(&enc_nonce.0),
            super::ENCRYPT_KEY_NAME: base32_encode(&enc_key),
            super::SIGNINING_KEY_SALT_NAME: base32_encode(&sign_salt.0),
            super::SIGNINING_KEY_NONCE_NAME: base32_encode(&sign_nonce.0),
            super::SIGNING_KEY_NAME: base32_encode(&sign_key),
        });
        Ok(serialize_private_key(super::KEY_TYPE_SODIUM, key, payload))
    } else {
        let enc_key = base32_encode(&key.get_enc_key().0);
        let sign_key = base32_encode(&key.get_sign_key().0);
        let payload = json!({
            super::ENCRYPT_KEY_NAME: enc_key,
            super::SIGNING_KEY_NAME: sign_key,
        });
        Ok(serialize_private_key(super::KEY_TYPE_SODIUM, key, payload))
    }
}

fn serialize_public_key<T>(key_type: &str, key: &T, key_payload: Value) -> Value
where
    T: PublicKey,
{
    let signatures = serialize_signatures(key.get_signatures());
    json!({
        super::KEY_TYPE_NAME: key_type,
        super::DEVICE_ID_NAME: key.get_device_id(),
        super::KEY_NAME: key_payload,
        super::SIGNATURES_NAME: signatures,
    })
}

fn serialize_signatures(sigs: &Vec<KeySignature>) -> Value {
    let mut signature_array = Vec::new();
    for sig in sigs {
        let sig_payload = base32_encode(&sig.signature);
        signature_array.push(json!({
            super::SIGNATURE_SIGNING_KEY_NAME: sig.signing_key_id,
            super::SIGNATURE_NAME: sig_payload,
        }));
    }
    Value::Array(signature_array)
}

fn serialize_private_key<T>(key_type: &str, key: &T, key_payload: Value) -> Value
where
    T: PrivateKey,
{
    json!({
        super::KEY_TYPE_NAME: key_type,
        super::DEVICE_ID_NAME: key.get_device_id(),
        super::KEY_NAME: key_payload,
    })
}

fn encrypt_key(payload: &[u8], pwd: &[u8], salt: &Salt, nonce: &Nonce) -> Result<Vec<u8>, ()> {
    let mut encrypt_key = [0; secretbox::KEYBYTES];
    pwhash::derive_key_interactive(&mut encrypt_key, pwd, salt)?;
    let key = secretbox::Key::from_slice(&encrypt_key).unwrap();
    Ok(secretbox::seal(payload, nonce, &key))
}
