use super::public::PublicKeyWrapper;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
struct KeyChain {
    timestamp: u128,
    keys: Vec<PublicKeyWrapper>,
    paths: HashMap<String, Vec<String>>,
}
