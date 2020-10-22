use super::prompt_user;
use super::send_requests;
use super::user_menu;
use crate::agent::command;

pub fn add_key() -> Result<(), String> {
    let key_name = prompt_user("Please enter a name for your new key");
    let key_choices = vec!["Sodium", "Yubikey", "Paper key"];

    let key_type_input = user_menu("Please enter a key type", &key_choices, Some(0));

    let key_type = match key_type_input {
        0 => command::KeyType::Sodium,
        1 => command::KeyType::Yubikey,
        2 => command::KeyType::PaperKey,
        _ => return Err("Unknown key type".to_string()),
    };

    let cmd = command::Command::AddKey(command::AddKeyRequest::new(key_name, key_type));

    let mut resp = send_requests(&vec![cmd]);
    super::process_unary_response_ignore(resp)
}
