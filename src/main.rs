mod agent;
mod config;
mod constants;
mod keys;
mod parse;
mod secret;
mod util;
use clap::App;
use clap::SubCommand;

fn main() {
    let matches = get_args().get_matches();
    match matches.subcommand() {
        ("generate", _) => {
            keys::generate::generate_key();
        }
        _ => println!("Unknown subcommand"),
    }
}

fn get_args<'a, 'b>() -> App<'a, 'b> {
    let app = App::new(constants::APP_NAME)
        .subcommand(SubCommand::with_name("generate").about("generate a new key pair"));
    app
}
