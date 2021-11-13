mod client;
mod config;
mod keys;
mod menu;
mod util;

fn main() {
    keys::gen_sodium_key();
}
