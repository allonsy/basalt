use super::keychain;
use super::passphrase;
use super::private;
use super::public;
use super::public::PublicKey;
use sodiumoxide::crypto::pwhash;
use std::collections::HashMap;

pub struct KeyStore {
    pub unlocked: HashMap<String, Box<dyn private::PrivateKey>>,
    pub session_unlocked: HashMap<String, Box<dyn private::PrivateKey>>,
    pub locked: HashMap<String, LockedKey>,
}

impl KeyStore {
    pub fn new() -> KeyStore {
        KeyStore {
            unlocked: HashMap::new(),
            session_unlocked: HashMap::new(),
            locked: HashMap::new(),
        }
    }

    pub fn reset_session(&mut self) {
        self.session_unlocked = HashMap::new();
    }

    pub fn try_unlock(&mut self, key_name: &str) -> Option<&dyn private::PrivateKey> {
        if !self.locked.contains_key(key_name) {
            return None;
        }
        let locked_key_result = self.locked.get_mut(key_name).unwrap().try_unlock(key_name);
        match locked_key_result {
            UnlockResult::Success => {
                self.session_unlocked.insert(
                    key_name.to_string(),
                    self.locked.get(key_name).unwrap().key.duplicate(),
                );
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

    pub fn try_load_key(
        &mut self,
        pub_key: &public::PublicKeyWrapper,
    ) -> Option<&dyn private::PrivateKey> {
        match pub_key {
            public::PublicKeyWrapper::Sodium(k) => {
                let key_name = pub_key.get_key_name();
                let dev_key = private::DeviceKey::read_key(key_name);
                if dev_key.is_err() {
                    return None;
                }
                let dev_key = dev_key.unwrap();

                match dev_key {
                    private::DeviceKey::Unencrypted(pkey) => {
                        self.session_unlocked
                            .insert(key_name.to_string(), Box::new(pkey));
                        return self.session_unlocked.get(key_name).map(|v| v.as_ref());
                    }
                    private::DeviceKey::Encrypted(pkey) => loop {
                        let pin = passphrase::get_pin(key_name);
                        if pin.is_err() {
                            return None;
                        }
                        let pin = pin.unwrap();
                        let dec_key = pkey.decrypt_key(pin.as_bytes());
                        if dec_key.is_err() {
                            continue;
                        }
                        let dec_key = dec_key.unwrap();
                        self.session_unlocked
                            .insert(key_name.to_string(), Box::new(dec_key));
                        return self.session_unlocked.get(key_name).map(|v| v.as_ref());
                    },
                }
            }
            public::PublicKeyWrapper::PaperKey(_) => {
                unimplemented!();
            }
            public::PublicKeyWrapper::Yubikey(_) => {
                unimplemented!();
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
    pub keys: KeyStore,
    chain: Option<keychain::KeyChain>,
}

impl State {
    pub fn new() -> State {
        State {
            chain: None,
            keys: KeyStore::new(),
        }
    }

    pub fn get_chain(&mut self) -> Result<&mut keychain::KeyChain, String> {
        if self.chain.is_some() {
            Ok(self.chain.as_mut().unwrap())
        } else {
            self.chain = Some(keychain::KeyChain::read_chain(self)?);
            Ok(self.chain.as_mut().unwrap())
        }
    }

    pub fn reset_session_keys(&mut self) {
        self.keys.reset_session();
    }
}
