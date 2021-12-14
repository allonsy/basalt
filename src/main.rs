mod agent;
mod client;
mod commands;
mod config;
mod keys;
mod menu;
mod reencrypt;
mod util;
mod vault;

fn main() {
    let app = commands::Application::new();
    app.run_app();
}
