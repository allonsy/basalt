use super::agent_cmd;
use super::keys;
use crate::constants;
use clap;

pub fn run_client() {
    let app = get_app();
    let ret_code = handle_app(app);
    std::process::exit(ret_code);
}

fn get_app<'a, 'b>() -> clap::App<'a, 'b> {
    clap::App::new(constants::APP_NAME)
        .version(clap::crate_version!())
        .author(clap::crate_authors!(", "))
        .about(constants::APP_DESC)
        .subcommand(
            clap::SubCommand::with_name("key")
                .about("Manage keychain")
                .subcommand(clap::SubCommand::with_name("add").about("add key")),
        )
        .subcommand(
            clap::SubCommand::with_name("agent")
                .about("Manage keystore agent")
                .subcommand(clap::SubCommand::with_name("reload").about("reload the agent"))
                .subcommand(clap::SubCommand::with_name("quit").about("Kill the agent")),
        )
}

fn handle_app<'a, 'b>(app: clap::App<'a, 'b>) -> i32 {
    let matches = app.get_matches();
    let res = match matches.subcommand() {
        ("key", Some(key_matches)) => match key_matches.subcommand() {
            ("add", _) => keys::add_key(),
            _ => {
                println!("{}", key_matches.usage());
                return 1;
            }
        },
        ("agent", Some(agent_matches)) => match agent_matches.subcommand() {
            ("reload", _) => agent_cmd::reload_agent(),
            ("quit", _) => agent_cmd::kill_agent(),
            _ => {
                println!("{}", agent_matches.usage());
                return 1;
            }
        },
        _ => {
            println!("No subcommand provided");
            println!("{}", matches.usage());
            return 1;
        }
    };
    if res.is_err() {
        eprintln!("{}", res.err().unwrap());
        return 1;
    }
    return 0;
}
