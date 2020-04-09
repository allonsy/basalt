mod pinentry;
mod protocol;
mod server;
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

fn read_message(conn: &mut UnixStream) -> Result<String, String> {
    let mut overflow = Vec::new();
    let mut size_buffer = [0; 16];
    let mut size_vec = Vec::new();
    let mut message_size = 0;
    let mut done = false;
    while done == false {
        let num_read = conn.read(&mut size_buffer);
        if num_read.is_err() {
            return Err(format!(
                "Unable to read from socket: {}",
                num_read.err().unwrap()
            ));
        }
        let num_read = num_read.unwrap();
        if num_read == 0 {
            return Err(format!("Incomplete message received"));
        }

        let mut to_size_buffer = true;
        for byte in &size_buffer[0..num_read] {
            if to_size_buffer {
                if *byte == 0xA {
                    let size_string = String::from_utf8(size_vec.clone());
                    if size_string.is_err() {
                        return Err(format!(
                            "Unable to parse size line: {}",
                            size_string.err().unwrap()
                        ));
                    }
                    let size_string = size_string.unwrap();
                    let parsed_size = size_string.parse::<usize>();
                    if parsed_size.is_err() {
                        return Err(format!(
                            "Unable to parse size line: {}",
                            parsed_size.err().unwrap()
                        ));
                    }
                    message_size = parsed_size.unwrap();
                    done = true;
                    to_size_buffer = false;
                } else {
                    size_vec.push(*byte);
                }
            } else {
                overflow.push(*byte);
                message_size -= 1;
            }
        }
    }

    let mut message_buffer = Vec::with_capacity(message_size);
    for _ in 0..message_size {
        message_buffer.push(0);
    }
    let message_result = conn.read_exact(message_buffer.as_mut_slice());
    if message_result.is_err() {
        return Err(format!(
            "Unable to read message: {}",
            message_result.err().unwrap()
        ));
    }
    overflow.extend_from_slice(&message_buffer);
    let message = String::from_utf8(overflow);
    if message.is_err() {
        return Err(format!(
            "Unable to parse message: {}",
            message.err().unwrap()
        ));
    }
    Ok(message.unwrap())
}
