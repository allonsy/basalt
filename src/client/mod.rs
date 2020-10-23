pub mod agent_cmd;
pub mod app;
pub mod decrypt;
pub mod encrypt;
pub mod keys;

use crate::agent;
use crate::config;
use agent::command;
use std::io;
use std::io::Write;
use std::os::unix::net::UnixStream;

fn get_agent_stream() -> Result<UnixStream, String> {
    let socket_path = config::get_agent_socket_file();
    if !socket_path.exists() {
        agent::spawn_agent()?;
    }

    UnixStream::connect(socket_path).map_err(|e| format!("Unable to connect to agent: {}", e))
}

fn send_requests(reqs: &[command::Command]) -> Vec<Result<command::Response, String>> {
    let socket = get_agent_stream();
    if socket.is_err() {
        eprintln!("{}", socket.err().unwrap());
        std::process::exit(1);
    }
    let mut socket = socket.unwrap();

    let resp = agent::send_request(&mut socket, reqs);
    if resp.is_err() {
        eprintln!("Failed to send commands to agent: {}", resp.err().unwrap());
        std::process::exit(1);
    }
    resp.unwrap()
}

fn process_unary_response(
    mut resp: Vec<Result<command::Response, String>>,
) -> Result<command::Response, String> {
    if resp.len() != 1 {
        return Err("no response received from agent".to_string());
    }

    let resp = resp.remove(0);
    resp
}

fn process_unary_response_ignore(
    resp: Vec<Result<command::Response, String>>,
) -> Result<(), String> {
    let agent_resp = process_unary_response(resp);
    if agent_resp.is_err() {
        return Err(agent_resp.err().unwrap());
    }
    return Ok(());
}

fn read_line() -> String {
    let mut user_input = String::new();
    let read_res = io::stdin().read_line(&mut user_input);
    if read_res.is_err() {
        eprintln!("Unable to read from user: {}", read_res.err().unwrap());
        std::process::exit(1);
    }
    user_input.trim().to_string()
}

fn prompt_user(prompt: &str) -> String {
    print!("{}: ", prompt);
    let _ = io::stdout().flush();
    read_line()
}

fn user_menu(prompt: &str, choices: &[&str], default: Option<usize>) -> usize {
    println!("{}", prompt);
    for (idx, choice) in choices.iter().enumerate() {
        let is_default = default.is_some() && default.as_ref().unwrap() == &idx;
        if !is_default {
            println!("{}) {}", idx + 1, choice);
        } else {
            println!("{}) {} [default]", idx + 1, choice);
        }
    }
    println!("*) Quit");
    print!("Please enter your selection as a number: ");
    let _ = io::stdout().flush();

    let user_choice = read_line();
    let user_choice = user_choice.trim();
    if user_choice.is_empty() {
        if default.is_some() {
            return default.unwrap();
        } else {
            eprintln!("No option provided, exiting...");
            std::process::exit(1);
        }
    }

    let user_index = str::parse::<usize>(user_choice);
    if user_index.is_err() {
        eprintln!("Unknown user input: '{}'", user_choice);
        std::process::exit(1);
    }
    let mut user_index = user_index.unwrap();
    user_index -= 1;
    if user_index < 0 || user_index >= choices.len() {
        std::process::exit(1);
    }
    return user_index;
}
