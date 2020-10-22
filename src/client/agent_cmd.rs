use crate::agent::command;

pub fn reload_agent() -> Result<(), String> {
    let commands = vec![command::Command::Reload];
    let resp = super::send_requests(&commands);
    super::process_unary_response_ignore(resp)
}

pub fn kill_agent() -> Result<(), String> {
    let commands = vec![command::Command::Quit];
    let resp = super::send_requests(&commands);
    super::process_unary_response_ignore(resp)
}
