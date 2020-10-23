use crate::agent::command;

pub fn decrypt_path(path: &str) -> Result<Vec<u8>, String> {
    let cmd = command::Command::Decrypt(command::DecryptRequest::new(path.to_string()));
    let cmds = vec![cmd];

    let resp = super::send_requests(&cmds);
    let resp = super::process_unary_response(resp)?;
    match resp {
        command::Response::Decrypt(contents) => Ok(contents),
        _ => Err("Agent response is malformed".to_string()),
    }
}
