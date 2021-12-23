use crate::util::exit;
use clap::App;

use super::Subcommand;

pub struct ReencryptCommand {}

impl ReencryptCommand {
    pub fn new() -> Self {
        ReencryptCommand {}
    }
}

impl Subcommand for ReencryptCommand {
    fn get_app(&self) -> App<'static, 'static> {
        App::new("reencrypt")
            .about("validates the store and reencrypts any incorrectly encrypted files")
    }

    fn run_cmd(&self, _: &clap::ArgMatches) {
        let mut client = super::get_client();
        let res = crate::reencrypt::validate(&mut client);

        if res.is_err() {
            exit(&res.err().unwrap(), 1);
        }
    }
}
