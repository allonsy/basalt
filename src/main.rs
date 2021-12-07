mod agent;
mod client;
mod config;
mod keys;
mod menu;
mod util;
mod vault;
mod reencrypt;

fn main() {
    keys::gen_sodium_key();
}
