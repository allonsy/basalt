use std::collections::HashMap;

use crate::keys::private::{OnDiskPrivateKey, PrivateKey};

use super::{Message, MessageResponse, MessageResponsePayload, SessionState};

pub(super) fn handle_message(state: &mut SessionState, message: Message) -> MessageResponse {
    match message {
        Message::Sign(payload) => sign_message(state, payload),
        Message::Decrypt(payloads) => decrypt_message(state, payloads),
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

fn decrypt_message(state: &mut SessionState, payloads: Vec<(String, Vec<u8>)>) -> MessageResponse {
    let mut payload_map = HashMap::new();

    for payload in payloads {
        payload_map.insert(payload.0, payload.1);
    }

    for (hash, key) in state.unlocked_keys.iter() {
        if payload_map.contains_key(hash) {
            let decrypted = key.decrypt(payload_map.get(hash).unwrap());
            if decrypted.is_ok() {
                return Ok(MessageResponsePayload::Decrypt(decrypted.unwrap()));
            }
        }
    }

    let shared_state = state
        .shared_state
        .lock()
        .map_err(|_| "Unable to lock state".to_string())?;

    for (hash, key) in shared_state.unlocked_keys.iter() {
        if payload_map.contains_key(hash) {
            let decrypted = key.decrypt(payload_map.get(hash).unwrap());
            if decrypted.is_ok() {
                return Ok(MessageResponsePayload::Decrypt(decrypted.unwrap()));
            }
        }
    }

    for (hash, key) in shared_state.locked_keys.iter() {
        if payload_map.contains_key(hash) {
            let ciphertext = payload_map.get(hash).unwrap();
            let unlocked_key = unlock_key(&key);
            if let Some(unlocked_key) = unlocked_key {
                let plaintext = unlocked_key.decrypt(&ciphertext);
                state.unlocked_keys.insert(hash.clone(), unlocked_key);
                if plaintext.is_ok() {
                    return Ok(MessageResponsePayload::Decrypt(plaintext.unwrap()));
                }
            }
        }
    }

    Err("No keys available to decrypt".to_string())
}

fn unlock_key(key: &OnDiskPrivateKey) -> Option<PrivateKey> {
    unimplemented!("Unlock key unimplemented");
}
