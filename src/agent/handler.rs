use crate::keys::private::{OnDiskPrivateKey, PrivateKey};

use super::{Message, MessageResponse, MessageResponsePayload, SessionState};

pub(super) fn handle_message(state: &mut SessionState, message: Message) -> MessageResponse {
    match message {
        Message::Sign(payload) => sign_message(state, payload),
        _ => Err(format!("Unknown command")),
    }
}

fn sign_message(state: &mut SessionState, payload: Vec<u8>) -> MessageResponse {
    for (hash, key) in state.unlocked_keys.iter() {
        let signed_payload = key.sign(&payload);
        return Ok(MessageResponsePayload::Sign(hash.clone(), signed_payload));
    }

    let shared_state = state
        .shared_state
        .lock()
        .map_err(|_| format!("Unable to lock state"))?;

    for (hash, key) in shared_state.unlocked_keys.iter() {
        let signed_payload = key.sign(&payload);
        return Ok(MessageResponsePayload::Sign(hash.clone(), signed_payload));
    }

    for (hash, key) in shared_state.locked_keys.iter() {
        let unlocked_key = unlock_key(&key);
        if let Some(unlocked_key) = unlocked_key {
            let signed_payload = unlocked_key.sign(&payload);
            state.unlocked_keys.insert(hash.clone(), unlocked_key);
            return Ok(MessageResponsePayload::Sign(hash.clone(), signed_payload));
        }
    }

    Err("No keys available to sign".to_string())
}

fn unlock_key(key: &OnDiskPrivateKey) -> Option<PrivateKey> {
    unimplemented!("Unlock key unimplemented");
}
