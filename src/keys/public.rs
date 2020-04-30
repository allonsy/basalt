use crate::config;
use crate::util::concat;
use serde::Deserialize;
use serde::Serialize;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::hash;
use sodiumoxide::crypto::sign;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::io::Read;

#[derive(Serialize, Deserialize)]
pub struct KeyChain {
    pub chain: Vec<ChainLink>,
}

impl KeyChain {
    fn new() -> KeyChain {
        KeyChain { chain: Vec::new() }
    }

    pub fn is_valid_device_id(&self, device_id: &str) -> bool {
        let mut valid_names = HashSet::new();
        for link in self.chain {
            match link.event {
                KeyEvent::NewKey(wrap) => valid_names.insert(wrap.device_id),
                KeyEvent::KeySignRequest(wrap) => valid_names.insert(wrap.device_id),
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

    pub fn verify(&self, head: Option<Vec<u8>>) -> Option<HashMap<String, &PublicKey>> {
        let mut trusted_keys: HashMap<String, &PublicKey> = HashMap::new();
        let mut is_trusted = false;
        let mut is_genesis = true;
        let mut parent_digest: Option<Vec<u8>> = None;

        for link in self.chain {
            if !is_genesis {
                if parent_digest.is_none() {
                    return None;
                }
                if &link.parent != parent_digest.as_ref().unwrap() {
                    return None;
                }
            } else {
                is_genesis = false;
            }

            match link.event {
                KeyEvent::NewKey(wrap) => {
                    let signing_key = trusted_keys.get(&link.signature.signing_key_id);
                    if signing_key.is_none() {
                        return None;
                    }
                    let sig_expected_payload =
                        get_hash(&concat(&link.parent, &link.event.get_digest()));
                    if signing_key
                        .unwrap()
                        .verify(&link.signature.payload, &sig_expected_payload)
                        == false
                    {
                        return None;
                    }
                    trusted_keys.insert(wrap.device_id, &wrap.key);
                }
                KeyEvent::KeyRevoke(wrap) => {
                    let signing_key = trusted_keys.get(&link.signature.signing_key_id);
                    if signing_key.is_none() {
                        return None;
                    }
                    let sig_expected_payload =
                        get_hash(&concat(&link.parent, &link.event.get_digest()));
                    if signing_key
                        .unwrap()
                        .verify(&link.signature.payload, &sig_expected_payload)
                        == false
                    {
                        return None;
                    }
                    trusted_keys.remove(&wrap.device_id);
                }
                KeyEvent::KeySignRequest(wrap) => {
                    let sig_expected_payload =
                        get_hash(&concat(&link.parent, &link.event.get_digest()));
                    if wrap
                        .key
                        .verify(&link.signature.payload, &sig_expected_payload)
                        == false
                    {
                        return None;
                    }
                }
            }
            let link_digest = link.get_digest();
            if head.is_some() && &link_digest == head.as_ref().unwrap() {
                is_trusted = true;
            }
        }

        if head.is_some() && !is_trusted {
            return None;
        } else {
            return Some(trusted_keys);
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ChainLink {
    parent: Vec<u8>,
    event: KeyEvent,
    signature: KeyEventSignature,
}

impl ChainLink {
    fn get_digest(&self) -> Vec<u8> {
        get_hash(&concat(
            &concat(&self.parent, &self.event.get_digest()),
            &self.signature.get_digest(),
        ))
    }
}

#[derive(Serialize, Deserialize)]
pub enum KeyEvent {
    NewKey(PublicKeyWrapper),
    KeySignRequest(PublicKeyWrapper),
    KeyRevoke(PublicKeyWrapper),
}

impl KeyEvent {
    pub fn get_digest(&self) -> Vec<u8> {
        match self {
            KeyEvent::NewKey(wrap) => get_hash(&concat("new".as_bytes(), &wrap.get_digest())),
            KeyEvent::KeySignRequest(wrap) => {
                get_hash(&concat("sign".as_bytes(), &wrap.get_digest()))
            }
            KeyEvent::KeyRevoke(wrap) => get_hash(&concat("revoke".as_bytes(), &wrap.get_digest())),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct KeyEventSignature {
    pub signing_key_id: String,
    pub payload: Vec<u8>,
}

impl KeyEventSignature {
    fn get_digest(&self) -> Vec<u8> {
        get_hash(&concat(self.signing_key_id.as_bytes(), &self.payload))
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyWrapper {
    device_id: String,
    key: PublicKey,
}

impl PublicKeyWrapper {
    fn get_digest(&self) -> Vec<u8> {
        get_hash(&concat(self.device_id.as_bytes(), &self.key.get_digest()))
    }

    fn verify(&self, payload: &[u8], expected: &[u8]) -> bool {
        self.key.verify(payload, expected)
    }
}

#[derive(Serialize, Deserialize)]
pub enum PublicKey {
    Sodium(SodiumKey),
}

impl PublicKey {
    fn get_digest(&self) -> Vec<u8> {
        match self {
            PublicKey::Sodium(skey) => {
                let bytes = concat("sodium".as_bytes(), &skey.get_digest());
                get_hash(&bytes)
            }
        }
    }

    fn verify(&self, payload: &[u8], expected: &[u8]) -> bool {
        match self {
            PublicKey::Sodium(skey) => skey.verify(payload, expected),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SodiumKey {
    enc_key: box_::PublicKey,
    sign_key: sign::PublicKey,
}

impl SodiumKey {
    fn get_digest(&self) -> Vec<u8> {
        let pkey_bytes = concat(&self.enc_key.0, &self.sign_key.0);
        get_hash(&pkey_bytes)
    }

    fn verify(&self, payload: &[u8], expected: &[u8]) -> bool {
        let sign_result = sign::verify(payload, &self.sign_key);
        if sign_result.is_err() {
            return false;
        }
        sign_result.unwrap() == expected
    }
}

pub fn get_head() -> Option<Vec<u8>> {
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
