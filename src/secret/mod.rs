mod decrypt;
mod encrypt;

pub use encrypt::encrypt;

const DEVICE_ID_KEY: &'static str = "device_id";
const KEY_KEY: &'static str = "key";
const NONCE_KEY: &'static str = "nonce";
const ENCRYPTED_PAYLOAD_KEY: &'static str = "payload";
const RECIPIENTS_KEY: &'static str = "recipients";
