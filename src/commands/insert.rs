use super::Subcommand;
use crate::{util, vault};
use clap::{App, Arg};
use std::{
    io::{stdin, Read},
    path::PathBuf,
};

const PATH_ARG_NAME: &'static str = "PATH";
pub struct InsertCommand {}

impl InsertCommand {
    pub fn new() -> Self {
        InsertCommand {}
    }
}

impl Subcommand for InsertCommand {
    fn get_app(&self) -> App<'static, 'static> {
        App::new("insert")
            .about("Insert (encrypt) a value in the store")
            .arg(
                Arg::with_name(PATH_ARG_NAME)
                    .value_name("path")
                    .required(true)
                    .help("path in the store to insert the secret"),
            )
    }

    fn run_cmd(&self, matches: &clap::ArgMatches) {
        let path = matches.value_of(PATH_ARG_NAME).unwrap();
        let path = PathBuf::from(path);

        let mut contents = Vec::new();
        let read_res = stdin().read_to_end(&mut contents);

        if read_res.is_err() {
            util::exit("unable to read from stdin", 1);
        }

        let mut client = super::get_client();
        let keychain = super::get_keyring(&mut client);

        let res = vault::Vault::create_vault(&keychain, &path, &contents);

        if res.is_err() {
            util::exit(&res.err().unwrap(), 1);
        }
    }
}
