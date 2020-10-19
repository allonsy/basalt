use super::passphrase;
use super::private;
use sodiumoxide::crypto::pwhash;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

pub struct KeyStore {
    pub unlocked: HashMap<String, Box<dyn private::PrivateKey>>,
    pub locked: HashMap<String, LockedKey>,
}

impl KeyStore {
    pub fn new() -> KeyStore {
        KeyStore {
            unlocked: HashMap::new(),
            locked: HashMap::new(),
        }
    }

    pub fn try_unlock(&mut self, key_name: &str) -> Option<&dyn private::PrivateKey> {
        if !self.locked.contains_key(key_name) {
            return None;
        }
        let locked_key_result = self.locked.get_mut(key_name).unwrap().try_unlock(key_name);
        match locked_key_result {
            UnlockResult::Success => {
                return Some(self.locked.get(key_name).unwrap().key.as_ref());
            }
            UnlockResult::Failure => {
                return None;
            }
            UnlockResult::Lockout => {
                self.locked.remove(key_name);
                return None;
            }
        }
    }
}

pub struct LockedKey {
    pub hash: pwhash::HashedPassword,
    pub num_tries: u32,
    pub max_tries: u32,
    pub key: Box<dyn private::PrivateKey>,
}

pub enum UnlockResult {
    Success,
    Failure,
    Lockout,
}

impl UnlockResult {
    pub fn success(&self) -> bool {
        match self {
            UnlockResult::Success => true,
            UnlockResult::Failure => false,
            UnlockResult::Lockout => false,
        }
    }

    pub fn is_success(&self) -> bool {
        match self {
            UnlockResult::Success => true,
            _ => false,
        }
    }

    pub fn is_failure(&self) -> bool {
        match self {
            UnlockResult::Failure => true,
            _ => false,
        }
    }

    pub fn is_lockout(&self) -> bool {
        match self {
            UnlockResult::Lockout => true,
            _ => false,
        }
    }
}

impl LockedKey {
    pub fn try_unlock(&mut self, key_name: &str) -> UnlockResult {
        while self.num_tries < self.max_tries {
            let pin = passphrase::get_pin(key_name);
            if pin.is_err() {
                return UnlockResult::Failure;
            }
            let pin = pin.unwrap();
            if pwhash::pwhash_verify(&self.hash, pin.as_bytes()) {
                self.num_tries = 0;
                return UnlockResult::Success;
            }
            self.num_tries += 1;
        }
        UnlockResult::Lockout
    }
}

pub struct State {
    pub keys: Arc<Mutex<KeyStore>>,
}

impl State {
    pub fn new() -> State {
        State {
            keys: Arc::new(Mutex::new(KeyStore::new())),
        }
    }
}

impl Clone for State {
    fn clone(&self) -> State {
        State {
            keys: self.keys.clone(),
        }
    }
}
