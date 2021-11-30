use super::{Message, MessageResponse, SessionState};

pub fn handle_message(state: SessionState, message: Message) -> MessageResponse {
    match message {
        Message::Sign(payload) => sign_message(state, payload),
        _ => Err(format!("Unknown command")),
    }
}

fn sign_message(state: SessionState, payload: Vec<u8>) -> MessageResponse {}
