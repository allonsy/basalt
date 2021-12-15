use clap::{crate_authors, crate_description, crate_version, App, ArgMatches};
use std::collections::HashMap;

use crate::{
    client::{self, Client},
    keys::keyring::{self, KeyChain},
    util,
};

mod generate;

trait Subcommand {
    fn get_app(&self) -> App<'static, 'static>;
    fn run_cmd(&self, matches: &ArgMatches);
}
pub struct Application {
    apps: HashMap<String, Box<dyn Subcommand>>,
}

impl Application {
    pub fn new() -> Application {
        let mut apps: HashMap<String, Box<dyn Subcommand>> = HashMap::new();
        apps.insert(
            "generate".to_string(),
            Box::new(generate::GenerateCommand::new()),
        );

        Application { apps: apps }
    }

    pub fn run_app(&self) {
        let mut base_app = App::new(crate_version!())
            .author(crate_authors!())
            .version(crate_version!())
            .setting(clap::AppSettings::ArgRequiredElseHelp)
            .about(crate_description!());

        for (cmd_name, cmd) in self.apps.iter() {
            base_app = base_app.subcommand(cmd.get_app());
        }

        let matches = base_app.get_matches();

        let (subcmd_name, subcmd_matches) = matches.subcommand();

        if let Some(matched_app) = self.apps.get(subcmd_name) {
            if subcmd_matches.is_some() {
                matched_app.run_cmd(subcmd_matches.unwrap())
            }
        }
    }
}

fn get_keyring(client: &mut Client) -> keyring::KeyChain {
    KeyChain::validate_keychain(client)
}

fn get_client() -> client::Client {
    let new_client = client::Client::new();
    if new_client.is_err() {
        util::exit("Unable to establish connection with the agent", 1);
    }

    new_client.unwrap()
}
