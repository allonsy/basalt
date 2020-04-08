use base32::Alphabet;

const BASE32_ALPHABET: Alphabet = Alphabet::RFC4648 { padding: true };

pub fn concat<T>(s1: &[T], s2: &[T]) -> Vec<T>
where
    T: std::clone::Clone,
{
    let mut ret = Vec::new();
    ret.extend_from_slice(s1);
    ret.extend_from_slice(s2);
    ret
}

pub fn base32_encode(msg: &[u8]) -> String {
    base32::encode(BASE32_ALPHABET, msg)
}

pub fn base32_decode(msg: &str) -> Option<Vec<u8>> {
    base32::decode(BASE32_ALPHABET, msg)
}
