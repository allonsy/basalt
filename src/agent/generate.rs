use super::keychain;
use super::passphrase;
use super::private;
use super::state;

pub fn generate_sodium_key(st: &mut state::State, key_name: &str) -> Result<(), String> {
    let mut keychain = keychain::KeyChain::read_chain(st)?;
    let pin = passphrase::generate_pin(key_name)?;
    let has_pin = !pin.is_empty();
    let new_key = private::SodiumPrivateKey::gen_key();
    let pub_key = new_key.get_public_key(key_name);

    let sec_key = if has_pin {
        private::DeviceKey::Encrypted(private::EncryptedSodiumKey::encrypt_key(
            &new_key,
            pin.as_bytes(),
        )?)
    } else {
        private::DeviceKey::Unencrypted(new_key)
    };

    keychain.add_key(pub_key);
    keychain.write_chain();
    sec_key.write_key(key_name);
    Ok(())
}
