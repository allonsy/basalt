use crate::config;
use crate::util::concat;
use serde::Deserialize;
use serde::Serialize;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::hash;
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::sign;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::Read;

#[cfg(test)]
mod tests;

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyChain {
    pub chain: Vec<ChainLink>,
}

impl KeyChain {
    pub fn new() -> KeyChain {
        KeyChain { chain: Vec::new() }
    }

    pub fn get_keychain() -> Result<KeyChain, String> {
        let chain_file = config::get_chain_file();
        let chain_contents = fs::read_to_string(chain_file)
            .map_err(|e| format!("Unable to read chain file: {}", e))?;
        serde_json::from_str(&chain_contents)
            .map_err(|e| format!("Unable to parse keychain json: {}", e))
    }

    pub fn write_keychain(&self) -> Result<(), String> {
        let chain_file = config::get_chain_file();
        let chain_bytes = serde_json::to_string(self)
            .map_err(|e| format!("Unable to marshal keychain to json: {}", e))?;
        fs::write(chain_file, chain_bytes.as_bytes())
            .map_err(|e| format!("Unable to write keychain file: {}", e))
    }

    pub fn is_valid_device_id(&self, device_id: &str) -> bool {
        let mut valid_names = HashSet::new();
        for link in self.chain.iter() {
            match &link.event {
                KeyEvent::NewKey(wrap) => valid_names.insert(wrap.device_id.to_string()),
                KeyEvent::KeySignRequest(wrap) => valid_names.insert(wrap.device_id.to_string()),
                KeyEvent::KeyRevoke(wrap) => valid_names.remove(&wrap.device_id),
            };
        }

        valid_names.contains(device_id)
    }

    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    pub fn get_digest(&self) -> Vec<u8> {
        if self.chain.is_empty() {
            return Vec::new();
        }
        self.chain[self.chain.len() - 1].get_digest()
    }

    pub fn get_verified_keys(&self) -> Option<HashMap<String, &PublicKey>> {
        let head = get_head()?;
        self.verify(head.clone(), false)
    }

    pub fn verify_merge(&self) -> bool {
        let head = get_head();
        if head.is_none() {
            return false;
        }
        let head = head.unwrap();
        let res = self.verify(head.clone(), true);
        if res.is_none() {
            return false;
        }
        let new_head = self.get_digest();
        if new_head != head {
            write_head(&new_head);
        }
        res.is_some()
    }

    fn verify(&self, head: Vec<u8>, is_merge: bool) -> Option<HashMap<String, &PublicKey>> {
        if self.is_empty() {
            return None;
        }
        if !is_merge && head != self.get_digest() {
            return None;
        }
        let mut trusted_keys: HashMap<String, &PublicKey> = HashMap::new();
        let mut is_trusted = false;
        let mut parent_digest: Option<Vec<u8>> = None;
        let chain_length = self.chain.len();

        for (index, link) in self.chain.iter().enumerate() {
            if index != 0 {
                if parent_digest.is_none() {
                    return None;
                }
                if &link.parent != parent_digest.as_ref().unwrap() {
                    return None;
                }
            }
            let link_digest = link.get_digest();
            parent_digest = Some(link_digest.clone());

            match &link.event {
                KeyEvent::NewKey(wrap) => {
                    let mut signing_key = trusted_keys.get(&link.signature.signing_key_id);
                    if index != 0 {
                        if signing_key.is_none() {
                            return None;
                        }
                    } else {
                        trusted_keys.insert(wrap.device_id.clone(), &wrap.key);
                        signing_key = trusted_keys.get(&wrap.device_id);
                    }
                    let sig_expected_payload = link.get_sig_payload();
                    if !signing_key
                        .unwrap()
                        .verify(&link.signature.payload, &sig_expected_payload)
                    {
                        println!("invalid signature");
                        return None;
                    }
                    trusted_keys.insert(wrap.device_id.clone(), &wrap.key);
                }
                KeyEvent::KeyRevoke(wrap) => {
                    let signing_key = trusted_keys.get(&link.signature.signing_key_id);
                    if signing_key.is_none() {
                        return None;
                    }
                    let sig_expected_payload =
                        get_hash(&concat(&[&link.parent, &link.event.get_digest()]));
                    if !signing_key
                        .unwrap()
                        .verify(&link.signature.payload, &sig_expected_payload)
                    {
                        return None;
                    }
                    trusted_keys.remove(&wrap.device_id);
                }
                KeyEvent::KeySignRequest(wrap) => {
                    if !is_merge {
                        return None;
                    }
                    let sig_expected_payload =
                        get_hash(&concat(&[&link.parent, &link.event.get_digest()]));
                    if !wrap
                        .key
                        .verify(&link.signature.payload, &sig_expected_payload)
                    {
                        return None;
                    }
                    if index != chain_length - 1 {
                        return None;
                    }
                }
            }
            if link_digest == head {
                is_trusted = true;
            }
        }

        if !is_trusted {
            return None;
        } else {
            return Some(trusted_keys);
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ChainLink {
    pub parent: Vec<u8>,
    pub event: KeyEvent,
    pub signature: KeyEventSignature,
}

impl ChainLink {
    pub fn get_digest(&self) -> Vec<u8> {
        get_hash(&concat(&[
            &self.parent,
            &self.event.get_digest(),
            &self.signature.get_digest(),
        ]))
    }

    pub fn get_sig_payload(&self) -> Vec<u8> {
        get_hash(&concat(&[&self.parent, &self.event.get_digest()]))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum KeyEvent {
    NewKey(PublicKeyWrapper),
    KeySignRequest(PublicKeyWrapper),
    KeyRevoke(PublicKeyWrapper),
}

impl KeyEvent {
    pub fn get_digest(&self) -> Vec<u8> {
        match self {
            KeyEvent::NewKey(wrap) => get_hash(&concat(&["new".as_bytes(), &wrap.get_digest()])),
            KeyEvent::KeySignRequest(wrap) => {
                get_hash(&concat(&["sign".as_bytes(), &wrap.get_digest()]))
            }
            KeyEvent::KeyRevoke(wrap) => {
                get_hash(&concat(&["revoke".as_bytes(), &wrap.get_digest()]))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyEventSignature {
    pub signing_key_id: String,
    pub payload: Vec<u8>,
}

impl KeyEventSignature {
    fn get_digest(&self) -> Vec<u8> {
        get_hash(&concat(&[self.signing_key_id.as_bytes(), &self.payload]))
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKeyWrapper {
    pub device_id: String,
    pub key: PublicKey,
}

impl PublicKeyWrapper {
    pub fn get_digest(&self) -> Vec<u8> {
        get_hash(&concat(&[
            self.device_id.as_bytes(),
            &self.key.get_digest(),
        ]))
    }

    pub fn verify(&self, payload: &[u8], expected: &[u8]) -> bool {
        self.key.verify(payload, expected)
    }

    pub fn encrypt(&self, payload: &[u8]) -> Vec<u8> {
        self.key.encrypt(payload)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum PublicKey {
    Sodium(SodiumKey),
}

impl PublicKey {
    fn get_digest(&self) -> Vec<u8> {
        match self {
            PublicKey::Sodium(skey) => {
                let bytes = concat(&["sodium".as_bytes(), &skey.get_digest()]);
                get_hash(&bytes)
            }
        }
    }

    pub fn verify(&self, payload: &[u8], expected: &[u8]) -> bool {
        match self {
            PublicKey::Sodium(skey) => skey.verify(payload, expected),
        }
    }

    pub fn encrypt(&self, payload: &[u8]) -> Vec<u8> {
        match self {
            PublicKey::Sodium(pkey) => pkey.encrypt(payload),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SodiumKey {
    pub enc_key: box_::PublicKey,
    pub sign_key: sign::PublicKey,
}

impl SodiumKey {
    fn get_digest(&self) -> Vec<u8> {
        let pkey_bytes = concat(&[&self.enc_key.0, &self.sign_key.0]);
        get_hash(&pkey_bytes)
    }

    fn verify(&self, payload: &[u8], expected: &[u8]) -> bool {
        let signature = sign::Signature::from_slice(payload);
        if signature.is_none() {
            return false;
        }
        let signature = signature.unwrap();
        sign::verify_detached(&signature, expected, &self.sign_key)
    }

    fn encrypt(&self, payload: &[u8]) -> Vec<u8> {
        sealedbox::seal(payload, &self.enc_key)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PaperKey {
    pub enc_nonce: Vec<u8>,
    pub enc_key: box_::PublicKey,
    pub sign_nonce: Vec<u8>,
    pub sign_key: sign::PublicKey,
}

impl PaperKey {
    fn get_digest(&self) -> Vec<u8> {
        let bytes = concat(&[
            &self.enc_nonce,
            &self.enc_key.0,
            &self.sign_nonce,
            &self.sign_key.0,
        ]);
        get_hash(&bytes)
    }

    fn to_sodium_key(&self) -> SodiumKey {
        SodiumKey {
            enc_key: self.enc_key.clone(),
            sign_key: self.sign_key.clone(),
        }
    }

    fn verify(&self, payload: &[u8], expected: &[u8]) -> bool {
        self.to_sodium_key().verify(payload, expected)
    }

    fn encrypt(&self, payload: &[u8]) -> Vec<u8> {
        self.to_sodium_key().encrypt(payload)
    }
}

fn get_head() -> Option<Vec<u8>> {
    let head_file = config::get_chain_head_file();
    let mut contents = String::new();
    let mut head_file = File::open(head_file).ok()?;
    head_file.read_to_string(&mut contents).ok()?;

    serde_json::from_str(&contents).ok()
}

pub fn write_head(new_head: &[u8]) {
    let head_file = config::get_chain_head_file();
    let contents = serde_json::to_string(new_head).unwrap();
    let write_res = fs::write(head_file, contents.as_bytes());
    if write_res.is_err() {
        eprintln!(
            "WARNING: UNABLE TO WRITE NEW CHAIN HEAD: {}",
            write_res.err().unwrap(),
        );
    }
}

fn get_hash(payload: &[u8]) -> Vec<u8> {
    let mut hash_bytes = Vec::new();
    hash_bytes.extend_from_slice(&hash::hash(payload).0);
    hash_bytes
}
