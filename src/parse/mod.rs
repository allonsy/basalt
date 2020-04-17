pub mod deserialize;
pub mod serialize;
use serde::Deserialize;
use serde::Serialize;

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
