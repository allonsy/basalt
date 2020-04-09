use std::io::Read;
use std::io::Write;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;

struct PinEntry {
    pin_process: Child,
}

impl PinEntry {
    fn new() -> Result<PinEntry, String> {
        let child = Command::new("pinentry")
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn();
        if child.is_err() {
            Err(format!(
                "Unable to call pinentry process: {}",
                child.err().unwrap()
            ))
        } else {
            Ok(PinEntry {
                pin_process: child.unwrap(),
            })
        }
    }

    fn read_line(&mut self) -> Result<String, String> {
        if self.pin_process.stdout.is_none() {
            return Err("Unable to read to pinentry stdout".to_string());
        }
        let stdout = self.pin_process.stdout.as_mut().unwrap();
        let mut line = Vec::new();
        loop {
            let mut buf = [0; 1];
            match stdout.read(&mut buf) {
                Ok(0) => {
                    return Err("Reached unexpected EOF".to_string());
                }
                Ok(_) => {
                    if buf[0] == 0xA {
                        let line_string = String::from_utf8(line);
                        if line_string.is_err() {
                            return Err(format!(
                                "Unable to parse pinentry response string: {}",
                                line_string.unwrap_err()
                            ));
                        }
                        let line_string = line_string.unwrap();
                        return Ok(line_string);
                    } else {
                        line.push(buf[0]);
                    }
                }
                Err(e) => {
                    return Err(format!("Unable to read from pinentry stdout: {}", e));
                }
            }
        }
    }

    fn send_command(&mut self, cmd: &str) -> Result<String, String> {
        if self.pin_process.stdin.is_none() {
            return Err("Unable to write to pinentry stdin".to_string());
        }
        let stdin = self.pin_process.stdin.as_mut().unwrap();

        let cmd_to_send = format!("{}\n", cmd);
        let write_res = stdin.write(cmd_to_send.as_bytes());
        if write_res.is_err() {
            return Err(format!(
                "Unable to write to pinentry stdin: {}",
                write_res.unwrap_err()
            ));
        }
        let write_flush = stdin.flush();
        if write_flush.is_err() {
            return Err(format!(
                "Unable to flush pinentry stdin: {}",
                write_flush.unwrap_err()
            ));
        }

        self.read_line()
    }
}

impl Drop for PinEntry {
    fn drop(&mut self) {
        self.pin_process.wait();
    }
}

enum PinEntryResponse {
    Success(String),
    Error(String),
}

impl PinEntryResponse {
    fn parse_response(msg: &str) -> PinEntryResponse {
        let msg_split: Vec<&str> = msg.splitn(2, " ").collect();
        if msg_split.len() != 2 {
            return PinEntryResponse::Error(format!(
                "Unable to parse pinentry response: '{}'",
                msg
            ));
        }
        let prefix = msg_split[0];
        let suffix = msg_split[1];
        if prefix == "ERR" {
            PinEntryResponse::Error(suffix.to_string())
        } else {
            PinEntryResponse::Success(suffix.to_string())
        }
    }

    fn unwrap(self) -> Result<String, String> {
        match self {
            PinEntryResponse::Success(s) => Ok(s),
            PinEntryResponse::Error(s) => Err(s),
        }
    }
}

pub fn get_pin(key_name: &str) -> Result<String, String> {
    let mut pinentry = PinEntry::new()?;
    let resp = pinentry.send_command(&format!("SETDESC Please enter PIN for {}", key_name))?;
    let _ = PinEntryResponse::parse_response(&resp).unwrap()?;
    let pin = pinentry.send_command("GETPIN")?;
    let resp = PinEntryResponse::parse_response(&pin).unwrap();
    let _ = pinentry.send_command("BYE");
    resp
}
