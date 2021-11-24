pub fn hexify(bytes: &[u8]) -> String {
    let mut hex_string = String::new();
    for byte in bytes {
        hex_string += &format!("{:02x}", byte);
    }
    hex_string
}

pub fn unhexify(hex_string: &str) -> Option<Vec<u8>> {
    let hex_string = hex_string.trim();

    if hex_string.len() % 2 != 0 {
        return None;
    }

    let mut bytes = Vec::new();

    let mut idx = 0;
    while idx < hex_string.len() {
        let substring = &hex_string[idx..idx + 2];

        let new_byte = u8::from_str_radix(substring, 16);
        if new_byte.is_err() {
            return None;
        }

        bytes.push(new_byte.unwrap());
        idx += 2;
    }

    Some(bytes)
}

pub fn exit(message: &str, status: i32) -> ! {
    eprintln!("{}", message);
    std::process::exit(status);
}

#[cfg(test)]
mod tests {

    #[test]
    fn hexify() {
        let hex = super::hexify(&vec![7, 9, 100, 11, 15, 76]);
        assert_eq!("0709640b0f4c", hex);
    }

    #[test]
    fn unhexify() {
        let bytes = super::unhexify("0709640b0f4c").unwrap();
        let expected: Vec<u8> = vec![7, 9, 100, 11, 15, 76];

        assert_eq!(expected, bytes);
    }

    #[test]
    fn unhexify_bad_chars() {
        let bytes = super::unhexify("070r640b0f4c");

        assert_eq!(None, bytes);
    }

    #[test]
    fn unhexify_bad_len() {
        let bytes = super::unhexify("070640b0f4c");

        assert_eq!(None, bytes);
    }
}
