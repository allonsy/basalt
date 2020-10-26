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

    println!("key type is: {}", key_type_input);
    let cmd = command::Command::AddKey(command::AddKeyRequest::new(
        key_name.clone(),
        key_type.clone(),
    ));

    let resp = send_requests(&vec![cmd]);
    let ret = super::process_unary_response(resp);
    if ret.is_ok() {
        println!("Successfully added key: {}", key_name);
    }
    if key_type == command::KeyType::PaperKey {
        match ret.unwrap() {
            command::Response::AddKey(Some(paperkey)) => {
                println!("Your paper key: {}", paperkey);
                println!("Please save that in a safe place!");
                Ok(())
            }
            _ => Err("Unexpected response from agent (expected paper key response)".to_string()),
        }
    } else {
        ret.map(|_| ())
    }
}
