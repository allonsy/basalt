use crate::secret::encrypt_secret;
use std::env;
use std::fs;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Result;
use std::path::PathBuf;
use std::process::Command;
use tempfile::NamedTempFile;

const DEFAULT_EDITOR: &'static str = "vi";

pub fn encrypt_message(path: &str, is_stdin: bool) {
    let sub_path = PathBuf::from(path);
    let message = if is_stdin {
        get_stdin()
    } else {
        get_interactive_input()
    };
    if message.is_err() {
        eprintln!(
            "Unable to read input to encrypt: {}",
            message.err().unwrap()
        );
        std::process::exit(1);
    }
    let message = message.unwrap();
    let encrypt_res = encrypt_secret(&sub_path, &message);
    if encrypt_res.is_err() {
        eprintln!("Unable to encrypt message: {}", encrypt_res.err().unwrap());
        std::process::exit(1);
    }
}

fn get_stdin() -> Result<Vec<u8>> {
    let mut stdin_bytes = Vec::new();
    std::io::stdin().read_to_end(&mut stdin_bytes)?;
    Ok(stdin_bytes)
}

fn get_interactive_input() -> Result<Vec<u8>> {
    let tmp = NamedTempFile::new()?;
    let tmp_path = tmp.into_temp_path();

    let editor = env::var("EDITOR").unwrap_or(DEFAULT_EDITOR.to_string());
    let editor = if editor.is_empty() {
        DEFAULT_EDITOR.to_string()
    } else {
        editor
    };

    let editor_cmd = Command::new(editor).arg(&tmp_path).status()?;
    if !editor_cmd.success() {
        return Err(Error::new(
            ErrorKind::Other,
            "EDITOR command didn't succeed",
        ));
    }

    fs::read(tmp_path)
}
