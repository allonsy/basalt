use crate::agent;
use crate::config;
use crate::keys::private::OnDiskPrivateKey;
use glob::glob;
use std::io::BufReader;
use std::os::unix::net::UnixStream;

pub struct Client {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Client {
    pub fn new() -> Result<Client, String> {
        agent::start_agent();

        let connection = UnixStream::connect(config::get_agent_socket_path());
        if connection.is_err() {
            return Err(format!(
                "Unable to connect to agent: {}",
                connection.err().unwrap()
            ));
        }

        let stream = connection.unwrap();
        let writer = stream
            .try_clone()
            .map_err(|_| "Unable to clone stream".to_string())?;
        let reader = BufReader::new(stream);

        Ok(Client { writer, reader })
    }

    fn send_message(&mut self, msg: agent::Message) -> agent::MessageResponse {
        agent::write_message(&mut self.writer, msg)
            .map_err(|_| "Unable to write to stream".to_string())?;

        let resp = agent::read_message(&mut self.reader)
            .map_err(|()| "Unable to read from stream".to_string())?;

        resp
    }

    pub fn sign_message(&mut self, payload: Vec<u8>) -> Result<(String, Vec<u8>), String> {
        let resp = self.send_message(agent::Message::Sign(payload))?;

        match resp {
            agent::MessageResponsePayload::Sign(h, p) => Ok((h, p)),
            _ => Err("Mismatched response from agent".to_string()),
        }
    }

    pub fn decrypt_message(&mut self, payloads: Vec<(String, Vec<u8>)>) -> Result<Vec<u8>, String> {
        let resp = self.send_message(agent::Message::Decrypt(payloads))?;

        match resp {
            agent::MessageResponsePayload::Decrypt(res) => Ok(res),
            _ => Err("Mismatched response from agent".to_string()),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.send_message(agent::Message::EndSession);
    }
}
