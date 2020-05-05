use crate::keys::private;
use crate::keys::public;

pub fn generate_key() {
    let keychain = public::KeyChain::get_keychain();
    if keychain.is_err() {
        eprintln!("Unable to read keychain file, please init repo first");
        std::process::exit(1);
    }
    let mut keychain = keychain.unwrap();

    private::generate_key(&mut keychain);
    let write_res = keychain.write_keychain();
    if write_res.is_err() {
        std::process::exit(1);
    }
}
