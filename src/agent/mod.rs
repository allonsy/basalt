mod client;
mod pinentry;
mod protocol;
mod server;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;

fn send_message(conn: &mut UnixStream, msg: &str) -> Result<(), String> {
    let msg_len = msg.len();
    let message = format!("{}\n{}", msg_len, msg);

    let write_res = conn.write(message.as_bytes());
    if write_res.is_err() {
        return Err(format!(
            "Unable to write to socket: {}",
            write_res.err().unwrap()
        ));
    }
    let write_res = write_res.unwrap();
    if write_res < message.len() {
        return Err(format!(
            "Unable to write entire message to socket. Wrote {} bytes, wanted {}",
            write_res,
            message.len()
        ));
    }
    Ok(())
}

fn read_message(conn: &mut BufReader<&UnixStream>) -> Result<String, String> {
    let mut size_line = String::new();
    let line_result = conn.read_line(&mut size_line);
    if line_result.is_err() {
        return Err(format!(
            "Unable to read size line: {}",
            line_result.unwrap_err()
        ));
    }
    if line_result.unwrap() == 0 {
        return Err("No size line provided".to_string());
    }
    let size = size_line.trim().parse::<usize>();
    if size.is_err() {
        return Err(format!("Unable to parse size line: {}", size.unwrap_err()));
    }
    let size = size.unwrap();

    let mut message_buf = Vec::new();
    for _ in 0..size {
        message_buf.push(0);
    }
    let message_result = conn.read_exact(&mut message_buf);
    if message_result.is_err() {
        Err(format!(
            "Unable to read message: {}",
            message_result.unwrap_err()
        ))
    } else {
        String::from_utf8(message_buf).map_err(|e| format!("Unable to parse message: {}", e))
    }
}
