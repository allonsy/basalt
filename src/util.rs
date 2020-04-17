use base32::Alphabet;
use std::io::Write;

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

pub fn prompt_user(prompt: &str) -> String {
    let mut input = String::new();
    print!("{}: ", prompt);
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

pub fn user_menu(prompt: &str, options: &[&str], default: Option<usize>) -> usize {
    println!("{}", prompt);
    for (pos, item) in options.iter().enumerate() {
        let is_default = default.is_some() && *default.as_ref().unwrap() == pos;
        if is_default {
            println!("{}*) {}", pos + 1, item);
        } else {
            println!("{}) {}", pos + 1, item);
        }
    }

    loop {
        print!("Enter your selection (* means default): ");
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let trimmed_input = input.trim();
        if trimmed_input.is_empty() && default.is_some() {
            return default.unwrap();
        }
        let parsed_input = trimmed_input.parse::<usize>();
        if parsed_input.is_ok() {
            return parsed_input.unwrap();
        }
    }
}
