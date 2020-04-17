use crate::keys::PrivateKey;
use crate::keys::PublicKey;
use crate::keys::SodiumPrivateKey;
use crate::keys::SodiumPublicKey;
use crate::util;
use crate::util::base32_encode;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::pwhash::Salt;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::Nonce;

pub fn serialize_sodium_pub_key(key: &SodiumPublicKey) -> Vec<u8> {
    let signatures = key
        .get_signatures()
        .iter()
        .map(|s| super::PublicKeySignatureFormat {
            signing_key_id: s.signing_key_id.clone(),
            signature: util::base32_encode(&s.signature),
        });
    let pub_key = super::PublicKeyWrapperFormat {
        device_id: key.get_device_id().to_string(),
        signatures: signatures.collect(),
        key: super::PublicKeyFormat::PublicSodiumKey(super::PublicSodiumKeyFormat {
            encrypt_key: util::base32_encode(&key.get_enc_key().0),
            sign_key: util::base32_encode(&key.get_sign_key().0),
        }),
    };

    serde_json::to_string(&pub_key).unwrap().into_bytes()
}

pub fn serialize_sodium_private_key(key: &SodiumPrivateKey, pwd: Option<&str>) -> Option<Vec<u8>> {
    let sec_key = super::PrivateKeyWrapperFormat {
        device_id: key.get_device_id().to_string(),
        key: super::PrivateKeyFormat::PrivateSodiumKey(if pwd.is_none() {
            super::PrivateSodiumKeyFormat::Unencrypted(super::PrivateUnencryptedSodiumKeyFormat {
                encrypt_key: util::base32_encode(&key.get_enc_key().0),
                sign_key: util::base32_encode(&key.get_sign_key().0),
            })
        } else {
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
            super::PrivateSodiumKeyFormat::Encrypted(super::PrivateEncryptedSodiumKeyFormat {
                encrypt_salt: base32_encode(&enc_salt.0),
                encrypt_nonce: util::base32_encode(&enc_nonce.0),
                encrypt_key: util::base32_encode(&enc_key),
                sign_salt: util::base32_encode(&sign_salt.0),
                sign_nonce: util::base32_encode(&sign_nonce.0),
                sign_key: util::base32_encode(&sign_key),
            })
        }),
    };
    Some(serde_json::to_string(&sec_key).unwrap().into_bytes())
}

fn encrypt_key(payload: &[u8], pwd: &[u8], salt: &Salt, nonce: &Nonce) -> Option<Vec<u8>> {
    let mut encrypt_key = [0; secretbox::KEYBYTES];
    pwhash::derive_key_interactive(&mut encrypt_key, pwd, salt).ok()?;
    let key = secretbox::Key::from_slice(&encrypt_key).unwrap();
    Some(secretbox::seal(payload, nonce, &key))
}
