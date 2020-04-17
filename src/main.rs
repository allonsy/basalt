mod agent;
mod config;
mod constants;
mod keys;
mod parse;
mod secret;
mod util;

fn main() {
    keys::generate::generate_key();
}
