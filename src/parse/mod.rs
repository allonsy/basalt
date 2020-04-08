pub mod deserialize;
pub mod serialize;

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
