pub mod deserialize;
pub mod serialize;
use serde::Deserialize;
use serde::Serialize;

const KEY_TYPE_NAME: &'static str = "key_type";
const DEVICE_ID_NAME: &'static str = "device_id";
const SIGNATURES_NAME: &'static str = "signatures";
const SIGNATURE_NAME: &'static str = "signature";
const KEY_NAME: &'static str = "key";
const ENCRYPT_KEY_NAME: &'static str = "encrypt_key";
const ENCRYPTION_KEY_SALT_NAME: &'static str = "encrypt_salt";
const ENCRYPT_KEY_NONCE_NAME: &'static str = "encrypt_nonce";
const SIGNINING_KEY_SALT_NAME: &'static str = "signing_salt";
const SIGNINING_KEY_NONCE_NAME: &'static str = "signing_nonce";
const SIGNING_KEY_NAME: &'static str = "signing_key";
const SIGNATURE_SIGNING_KEY_NAME: &'static str = "signing_key";

const KEY_TYPE_SODIUM: &'static str = "sodium";

#[derive(Serialize, Deserialize)]
struct PublicKeyWrapperFormat {
    device_id: String,
    key: PublicKeyFormat,
    signatures: Vec<PublicKeySignatureFormat>,
}

#[derive(Serialize, Deserialize)]
enum PublicKeyFormat {
    PublicSodiumKey(PublicSodiumKeyFormat),
}

#[derive(Serialize, Deserialize)]
struct PublicSodiumKeyFormat {
    encrypt_key: String,
    sign_key: String,
}

#[derive(Serialize, Deserialize)]
struct PublicKeySignatureFormat {
    signing_key_id: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct PrivateKeyWrapperFormat {
    device_id: String,
    key: PrivateKeyFormat,
}

#[derive(Serialize, Deserialize)]
enum PrivateKeyFormat {
    PrivateSodiumKey(PrivateSodiumKeyFormat),
}

#[derive(Serialize, Deserialize)]
enum PrivateSodiumKeyFormat {
    Encrypted(PrivateEncryptedSodiumKeyFormat),
    Unencrypted(PrivateUnencryptedSodiumKeyFormat),
}

#[derive(Serialize, Deserialize)]
struct PrivateUnencryptedSodiumKeyFormat {
    encrypt_key: String,
    sign_key: String,
}

#[derive(Serialize, Deserialize)]
struct PrivateEncryptedSodiumKeyFormat {
    encrypt_salt: String,
    encrypt_nonce: String,
    encrypt_key: String,
    sign_salt: String,
    sign_nonce: String,
    sign_key: String,
}
