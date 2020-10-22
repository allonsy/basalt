mod agent;
mod client;
mod config;
mod constants;

pub fn main() {
    client::app::run_client();
}
