mod agent;
mod client;
mod config;
mod keys;
mod menu;
mod reencrypt;
mod util;
mod vault;

fn main() {
    keys::gen_sodium_key();
}
