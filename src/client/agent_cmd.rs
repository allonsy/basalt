use crate::agent;
use crate::agent::command;

pub fn reload_agent() -> Result<(), String> {
    let commands = vec![command::Command::Reload];
    let resp = super::send_requests(&commands);
    super::process_unary_response_ignore(resp)
}

pub fn kill_agent() -> Result<(), String> {
    let socket = super::get_agent_stream();
    if socket.is_err() {
        return Err(format!("{}", socket.err().unwrap()));
    }
    let mut socket = socket.unwrap();
    let commands = vec![command::Command::Quit];
    agent::write_message(&mut socket, &commands)
}
