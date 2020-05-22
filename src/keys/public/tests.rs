use super::ChainLink;
use super::KeyChain;
use super::KeyEvent;
use super::KeyEventSignature;
use super::PublicKey;
use super::PublicKeyWrapper;
use super::SodiumKey;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;

struct TestLink {
    operation: usize,
    id: String,
    enc_key: box_::SecretKey,
    sign_key: sign::SecretKey,
    sign_index: usize,
}

impl TestLink {
    fn new(
        operation: usize,
        id: String,
        key: (box_::SecretKey, sign::SecretKey),
        index: usize,
    ) -> TestLink {
        TestLink {
            operation,
            id,
            enc_key: key.0,
            sign_key: key.1,
            sign_index: index,
        }
    }

    fn get_chain(links: Vec<TestLink>) -> KeyChain {
        let mut chain = KeyChain::new();
        let mut parent = Vec::new();
        for link in links.iter() {
            let key_wrapper =
                get_sodium_key(&link.id, &(link.enc_key.clone(), link.sign_key.clone()));
            let new_event = if link.operation == 0 {
                KeyEvent::NewKey(key_wrapper)
            } else if link.operation == 1 {
                KeyEvent::KeySignRequest(key_wrapper)
            } else if link.operation == 2 {
                KeyEvent::KeyRevoke(key_wrapper)
            } else {
                panic!("Unknown link operation: {}", link.operation)
            };
            let mut new_link = ChainLink {
                parent: parent,
                event: new_event,
                signature: get_empty_sig(&links[link.sign_index].id),
            };
            let sig = sign::sign_detached(
                &new_link.get_sig_payload(),
                &links[link.sign_index].sign_key,
            );
            new_link.signature.payload = sig.0.to_vec();
            chain.chain.push(new_link);
            parent = chain.get_digest();
        }
        chain
    }
}

#[test]
fn test_verify_empty_chain() {
    let chain = KeyChain::new();
    assert!(
        chain.verify(Vec::new(), false).is_none(),
        "emtpy chain shouldn't be valid"
    );
}

#[test]
fn test_verify_good_chain() {
    let key1 = get_fresh_key();
    let key2 = get_fresh_key();
    let chain = TestLink::get_chain(vec![
        TestLink::new(0, "sod1".to_string(), key1, 0),
        TestLink::new(0, "sod2".to_string(), key2, 0),
    ]);
    let head = chain.get_digest();

    let trusted_keys = chain.verify(head, false);
    assert!(trusted_keys.is_some(), "valid simple chain isn't valid",);

    let trusted_keys = trusted_keys.unwrap();
    assert!(trusted_keys.contains_key("sod1"), "sod1 isn't trusted");
    assert!(trusted_keys.contains_key("sod2"), "sod2 isn't trusted");
}

#[test]
fn test_verify_good_revoke() {
    let key1 = get_fresh_key();
    let key2 = get_fresh_key();
    let key3 = get_fresh_key();
    let chain = TestLink::get_chain(vec![
        TestLink::new(0, "sod1".to_string(), key1.clone(), 0),
        TestLink::new(0, "sod2".to_string(), key2, 0),
        TestLink::new(2, "sod1".to_string(), key1, 1),
        TestLink::new(0, "sod3".to_string(), key3, 1),
    ]);
    let head = chain.get_digest();

    let trusted_keys = chain.verify(head, false);
    assert!(trusted_keys.is_some(), "valid simple chain isn't valid",);

    let trusted_keys = trusted_keys.unwrap();
    assert!(
        !trusted_keys.contains_key("sod1"),
        "revoked sod1 is still trusted"
    );
    assert!(trusted_keys.contains_key("sod2"), "sod2 isn't trusted");
    assert!(trusted_keys.contains_key("sod3"), "sod3 isn't trusted");
}

#[test]
fn test_verify_bad_parent() {
    let key1 = get_fresh_key();
    let key2 = get_fresh_key();
    let mut chain = TestLink::get_chain(vec![
        TestLink::new(0, "sod1".to_string(), key1, 0),
        TestLink::new(0, "sod2".to_string(), key2, 0),
    ]);
    let mut old_parent = chain.chain[1].parent.clone();
    old_parent[0] = !old_parent[0];
    chain.chain[1].parent = old_parent;
    let head = chain.get_digest();

    assert!(
        chain.verify(head, false).is_none(),
        "invalid parent reported as valid",
    );
}

#[test]
fn test_verify_bad_sig() {
    let key1 = get_fresh_key();
    let key2 = get_fresh_key();
    let mut chain = TestLink::get_chain(vec![
        TestLink::new(0, "sod1".to_string(), key1, 0),
        TestLink::new(0, "sod2".to_string(), key2, 0),
    ]);
    chain.chain[1].signature.payload[0] = !chain.chain[1].signature.payload[0];
    let head = chain.get_digest();

    assert!(
        chain.verify(head, false).is_none(),
        "invalid signature reported as valid",
    );
}

#[test]
fn test_verify_sign_request() {
    let key1 = get_fresh_key();
    let key2 = get_fresh_key();
    let chain = TestLink::get_chain(vec![
        TestLink::new(0, "sod1".to_string(), key1, 0),
        TestLink::new(1, "sod2".to_string(), key2, 1),
    ]);
    let head = chain.chain[0].get_digest();

    let trusted_keys = chain.verify(head, true);
    assert!(
        trusted_keys.is_some(),
        "key signing request should be valid",
    );
    let trusted_keys = trusted_keys.unwrap();
    assert!(trusted_keys.contains_key("sod1"), "sod1 should be valid");
    assert!(
        !trusted_keys.contains_key("sod2"),
        "sod2 KSR shouldn't be a valid key"
    );
}

#[test]
fn test_verify_sign_request_bad_head() {
    let key1 = get_fresh_key();
    let key2 = get_fresh_key();
    let chain = TestLink::get_chain(vec![
        TestLink::new(0, "sod1".to_string(), key1, 0),
        TestLink::new(1, "sod2".to_string(), key2, 1),
    ]);
    let mut head = chain.chain[0].get_digest();
    head[0] = !head[0];

    let trusted_keys = chain.verify(head, true);
    assert!(
        trusted_keys.is_none(),
        "bad head with KSR shouldn't be valid",
    );
}

#[test]
fn test_verify_ksr_no_merge() {
    let key1 = get_fresh_key();
    let key2 = get_fresh_key();
    let chain = TestLink::get_chain(vec![
        TestLink::new(0, "sod1".to_string(), key1, 0),
        TestLink::new(1, "sod2".to_string(), key2, 1),
    ]);
    let head = chain.get_digest();

    let trusted_keys = chain.verify(head, false);
    assert!(
        trusted_keys.is_none(),
        "KSR shouldn't be allowed in non-merge mode",
    );
}

#[test]
fn test_verify_revoked_key_sign() {
    let key1 = get_fresh_key();
    let key2 = get_fresh_key();
    let key3 = get_fresh_key();
    let chain = TestLink::get_chain(vec![
        TestLink::new(0, "sod1".to_string(), key1.clone(), 0),
        TestLink::new(1, "sod2".to_string(), key2, 1),
        TestLink::new(2, "sod1".to_string(), key1, 0),
        TestLink::new(0, "sod3".to_string(), key3, 0),
    ]);
    let head = chain.chain[0].get_digest();

    let trusted_keys = chain.verify(head, false);
    assert!(trusted_keys.is_none(), "Revoked Keys cannot sign new keys",);
}

#[test]
fn test_verify_bad_head() {
    let key1 = get_fresh_key();
    let key2 = get_fresh_key();
    let chain = TestLink::get_chain(vec![
        TestLink::new(0, "sod1".to_string(), key1, 0),
        TestLink::new(0, "sod2".to_string(), key2, 0),
    ]);
    let head = chain.chain[0].get_digest();

    assert!(
        chain.verify(head, false).is_none(),
        "invalid head reported as valid",
    );
}

fn get_empty_sig(id: &str) -> KeyEventSignature {
    KeyEventSignature {
        signing_key_id: id.to_string(),
        payload: Vec::new(),
    }
}

fn get_sodium_key(id: &str, keys: &(box_::SecretKey, sign::SecretKey)) -> PublicKeyWrapper {
    let (enc_key, sign_key) = keys;
    PublicKeyWrapper {
        device_id: id.to_string(),
        key: PublicKey::Sodium(SodiumKey {
            enc_key: enc_key.public_key(),
            sign_key: sign_key.public_key(),
        }),
    }
}

fn get_fresh_key() -> (box_::SecretKey, sign::SecretKey) {
    let (_, enc_key) = box_::gen_keypair();
    let (_, sign_key) = sign::gen_keypair();
    (enc_key, sign_key)
}
