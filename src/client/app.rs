use super::agent_cmd;
use super::decrypt;
use super::encrypt;
use super::keys;
use crate::constants;
use clap;
use std::io::Write;

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
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            clap::SubCommand::with_name("key")
                .about("Manage keychain")
                .setting(clap::AppSettings::SubcommandRequiredElseHelp)
                .subcommand(clap::SubCommand::with_name("add").about("add key")),
        )
        .subcommand(
            clap::SubCommand::with_name("encrypt")
                .about("Encrypt secrets in the store")
                .arg(
                    clap::Arg::with_name("path")
                        .long("path")
                        .takes_value(true)
                        .help("path to save secret in the store")
                        .required(true),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("decrypt")
                .about("Decrypt secrets in the store")
                .arg(
                    clap::Arg::with_name("path")
                        .long("path")
                        .takes_value(true)
                        .help("path to decrypt secret in the store")
                        .required(true),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("agent")
                .setting(clap::AppSettings::SubcommandRequiredElseHelp)
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
            _ => panic!("subcommand required"),
        },
        ("encrypt", Some(enc_matches)) => {
            let path = enc_matches.value_of("path").unwrap();
            encrypt::encrypt_file(path)
        }
        ("decrypt", Some(dec_matches)) => {
            let path = dec_matches.value_of("path").unwrap();
            let contents = decrypt::decrypt_path(path);
            if contents.is_err() {
                Err(contents.err().unwrap())
            } else {
                std::io::stdout().write_all(&contents.unwrap()).unwrap();
                println!("");
                Ok(())
            }
        }
        ("agent", Some(agent_matches)) => match agent_matches.subcommand() {
            ("reload", _) => agent_cmd::reload_agent(),
            ("quit", _) => agent_cmd::kill_agent(),
            _ => panic!("subcommand required"),
        },
        _ => panic!("subcommand required"),
    };
    if res.is_err() {
        eprintln!("{}", res.err().unwrap());
        return 1;
    }
    return 0;
}
