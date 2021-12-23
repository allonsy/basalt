use crate::{
    keys::{self, keyring},
    menu::prompt,
};
use clap::App;

use super::Subcommand;

pub struct GenerateCommand {}

impl GenerateCommand {
    pub fn new() -> Self {
        GenerateCommand {}
    }
}

impl Subcommand for GenerateCommand {
    fn get_app(&self) -> clap::App<'static, 'static> {
        App::new("generate").about("generate a new key pair")
    }

    fn run_cmd(&self, _: &clap::ArgMatches) {
        generate_key();
    }
}

fn generate_key() {
    let key_name = prompt("please enter a name for the new key:");

    let private_key = keys::private::PrivateKey::gen_sodium_key(key_name);
    let pub_key = private_key.get_public_key();

    let disk_private_key = keys::private::OnDiskPrivateKey::wrap_key(private_key);
    let disk_pub_key = keys::public::FullPublicKey::new(&pub_key);
    let mut client = super::get_client();
    let keychain = super::get_keyring(&mut client);

    if !keychain.validated_keys.is_empty() {
        keyring::sign_key(&mut vec![disk_pub_key.clone()], &mut client);
        disk_private_key.write_key();
    } else {
        disk_pub_key.write_key();
        disk_private_key.write_key();
    }
}
