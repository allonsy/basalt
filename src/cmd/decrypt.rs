use crate::secret::decrypt;
use std::io;
use std::io::Write;
use std::path::PathBuf;

pub fn decrypt_file(path: &str) {
    let path = PathBuf::from(path);
    let decrypted_contents = decrypt::decrypt(&path);
    if decrypted_contents.is_err() {
        eprintln!(
            "Unable to decrypt contents: {}",
            decrypted_contents.err().unwrap()
        );
        std::process::exit(1);
    }

    let output_res = io::stdout().write_all(&decrypted_contents.unwrap());
    if output_res.is_err() {
        eprintln!("Unable to write bytes to stdout");
        std::process::exit(1);
    }
}
