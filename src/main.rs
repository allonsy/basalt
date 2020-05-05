mod agent;
mod cmd;
mod config;
mod constants;
mod keys;
mod secret;
mod util;
use clap::App;
use clap::Arg;
use clap::SubCommand;

fn main() {
    let matches = get_args().get_matches();
    match matches.subcommand() {
        ("generate", _) => {
            cmd::generate::generate_key();
        }
        ("init", _) => {
            cmd::init::init();
        }
        ("encrypt", args) => {
            let args = args.unwrap();
            let path = args.value_of("path").unwrap();
            let is_stdin = args.value_of("stdin").is_some();
            cmd::encrypt::encrypt_message(path, is_stdin);
        }
        ("decrypt", args) => {
            let args = args.unwrap();
            let path = args.value_of("path").unwrap();
            cmd::decrypt::decrypt_file(path);
        }
        ("reencrypt", args) => {
            let args = args.unwrap();
            let path = args.value_of("path").unwrap();
            cmd::reencrypt::reencrypt(path);
        }
        _ => println!("Unknown subcommand"),
    }
}

fn get_args<'a, 'b>() -> App<'a, 'b> {
    let app = App::new(constants::APP_NAME)
        .subcommand(SubCommand::with_name("generate").about("generate a new key pair"))
        .subcommand(SubCommand::with_name("init").about("Initialize a new secret store"))
        .subcommand(
            SubCommand::with_name("encrypt")
                .about("Encrypt a file")
                .arg(
                    Arg::with_name("path")
                        .required(true)
                        .help("path to file to encrypt"),
                )
                .arg(
                    Arg::with_name("stdin")
                        .required(false)
                        .long("stdin")
                        .help("Read from stdin rather than from a file"),
                ),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .about("Decrypt a file")
                .arg(
                    Arg::with_name("path")
                        .required(true)
                        .help("path to file to decrypt"),
                ),
        )
        .subcommand(
            SubCommand::with_name("reencrypt")
                .about("Reencrypt a file")
                .arg(
                    Arg::with_name("path")
                        .required(true)
                        .help("path to file to reencrypt"),
                ),
        );
    app
}
