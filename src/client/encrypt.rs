use crate::agent::command;
use crate::constants;
use std::env;
use std::fs;
use std::process::Command;
use tempfile::NamedTempFile;

pub fn get_editor() -> String {
    let editor_var = env::var("EDITOR");
    if editor_var.is_ok() {
        let editor_var = editor_var.unwrap();
        if !editor_var.is_empty() {
            return editor_var;
        }
    }

    constants::DEFAULT_EDITOR.to_string()
}

pub fn get_tmp_file() -> Result<NamedTempFile, String> {
    NamedTempFile::new().map_err(|e| format!("Unable to allocated temporary file: {}", e))
}

pub fn edit_tmp_file(file: NamedTempFile) -> Result<Vec<u8>, String> {
    let edit_cmd = Command::new(get_editor())
        .arg(file.path().as_os_str())
        .status()
        .map_err(|e| format!("Unable to execute editor command: {}", e))?;
    if !edit_cmd.success() {
        return Err(format!(
            "Editor returned non-success status code: {}",
            edit_cmd.code().unwrap(),
        ));
    }

    fs::read(file.path()).map_err(|e| format!("Unable to read from temp file: {}", e))
}

pub fn encrypt_contents(path: &str, contents: Vec<u8>) -> Result<(), String> {
    let cmd = command::Command::Encrypt(command::EncryptRequest::new(path.to_string(), contents));
    let cmds = vec![cmd];

    let resp = super::send_requests(&cmds);
    super::process_unary_response_ignore(resp)
}

pub fn encrypt_file(path: &str) -> Result<(), String> {
    let tmp_file = get_tmp_file()?;
    let contents = edit_tmp_file(tmp_file)?;

    encrypt_contents(path, contents)
}
