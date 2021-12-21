use std::{
    io::{stdin, stdout, Read, Write},
    path::PathBuf,
};

use clap::{App, Arg};

use crate::{
    util::{self, exit},
    vault,
};

use super::Subcommand;

const PATH_ARG_NAME: &'static str = "PATH";
pub struct ShowCommand {}

impl ShowCommand {
    pub fn new() -> Self {
        ShowCommand {}
    }
}

impl Subcommand for ShowCommand {
    fn get_app(&self) -> App<'static, 'static> {
        App::new("show").arg(
            Arg::with_name(PATH_ARG_NAME)
                .value_name("path")
                .required(true)
                .help("path in the store to decrypt"),
        )
    }

    fn run_cmd(&self, matches: &clap::ArgMatches) {
        let path = matches.value_of(PATH_ARG_NAME).unwrap();
        let path = PathBuf::from(path);

        let mut client = super::get_client();

        let decrypted_bytes = vault::Vault::open_vault_path(&path, &mut client);
        match decrypted_bytes {
            Ok(bytes) => {
                stdout().write_all(&bytes).unwrap();
            }
            Err(()) => {
                exit(&format!("Unable to decrypt vault at path {:?}", path), 1);
            }
        }
    }
}
