use super::private;
use super::private::PrivateKey;
use super::private::UnencryptedSodiumPrivateKey;
use super::public::PaperKey;
use crate::util::concat;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::sign;
use sodiumoxide::randombytes::randombytes;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

const LANG_SIZE: usize = 2048;

pub fn generate_paper_key() -> Result<(Vec<String>, PaperKey), String> {
    let lang_map = get_language_map(&get_language())?;
    let (words, nums) = get_random_seed(&lang_map);
    let seed_bytes = nums_to_bytes(&nums);
    let enc_nonce = randombytes(box_::SEEDBYTES - seed_bytes.len());
    let sign_nonce = randombytes(sign::SEEDBYTES - seed_bytes.len());

    let enc_seed = box_::Seed::from_slice(&concat(&[&enc_nonce, &seed_bytes])).unwrap();
    let sign_seed = sign::Seed::from_slice(&concat(&[&sign_nonce, &seed_bytes])).unwrap();

    let (enc_key, _) = box_::keypair_from_seed(&enc_seed);
    let (sign_key, _) = sign::keypair_from_seed(&sign_seed);

    Ok((
        words,
        PaperKey {
            enc_nonce,
            enc_key,
            sign_nonce,
            sign_key,
        },
    ))
}

pub fn decode_paper_key(pkey: &PaperKey, words: &Vec<String>) -> Result<PrivateKey, String> {
    let lang_map = get_language_map(&get_language())?;
    let rev_map = get_reverse_map(&lang_map);

    let mut nums = Vec::new();
    for word in words {
        let index = rev_map.get(word);
        if index.is_none() {
            return Err(format!("Invalid code word: {}", word));
        }
        let index = index.unwrap();
        nums.push(*index);
    }
    let seed_bytes = nums_to_bytes(&nums);
    let enc_seed = box_::Seed::from_slice(&concat(&[&pkey.enc_nonce, &seed_bytes]))
        .ok_or("Invalid paper key encrypt seed")?;
    let sign_seed = sign::Seed::from_slice(&concat(&[&pkey.sign_nonce, &seed_bytes]))
        .ok_or("Invalid paper key sign seed")?;

    let (enc_pubkey, enc_seckey) = box_::keypair_from_seed(&enc_seed);
    let (sign_pubkey, sign_seckey) = sign::keypair_from_seed(&sign_seed);
    if enc_pubkey != pkey.enc_key || sign_pubkey != pkey.sign_key {
        return Err("Paper key phrase is invalid".to_string());
    }

    let inner_key = UnencryptedSodiumPrivateKey {
        encrypt_key: enc_seckey,
        sign_key: sign_seckey,
    };
    Ok(PrivateKey::PaperKey(private::PaperKey { key: inner_key }))
}

fn nums_to_bytes(nums: &[usize]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut bits = Vec::new();
    for num in nums {
        bits.extend_from_slice(&index_to_bit_array(*num));
    }

    let mut power = 0;
    let mut cur_byte = 0;

    for bit in bits {
        if bit {
            cur_byte += 1 << power;
        }
        power += 1;
        if power == 8 {
            bytes.push(cur_byte as u8);
            power = 0;
            cur_byte = 0;
        }
    }
    bytes
}

fn index_to_bit_array(mut num: usize) -> Vec<bool> {
    let mut bits = Vec::new();
    while num > 0 {
        if num % 2 != 0 {
            bits.push(true)
        } else {
            bits.push(false)
        }
        num = num >> 1;
    }
    bits
}

fn get_random_seed(lang_map: &HashMap<usize, String>) -> (Vec<String>, Vec<usize>) {
    let num_words = 16;
    let mut words = Vec::new();
    let mut nums = Vec::new();
    let rand_bytes = randombytes(num_words);
    for i in 0..num_words {
        let index = (rand_bytes[i] % (LANG_SIZE as u8)) as usize;
        words.push(lang_map.get(&index).unwrap().to_string());
        nums.push(index);
    }
    (words, nums)
}

fn get_language() -> String {
    "english".to_string()
}

fn get_language_map(lang: &str) -> Result<HashMap<usize, String>, String> {
    let lang_file_name: PathBuf = vec!["language".to_string(), format!("{}.txt", lang)]
        .iter()
        .collect();
    let mut lang_file = File::open(&lang_file_name).map_err(|e| {
        format!(
            "Unable to read paper key language for lang: {}, err: {}",
            lang, e
        )
    })?;
    let mut lang_contents = String::new();
    lang_file
        .read_to_string(&mut lang_contents)
        .map_err(|e| format!("Unable to read lang file: {}", e))?;

    let mut lang_map = HashMap::new();
    for (idx, word) in lang_contents.lines().enumerate() {
        lang_map.insert(idx, word.trim().to_string());
    }
    Ok(lang_map)
}

fn get_reverse_map(lang_map: &HashMap<usize, String>) -> HashMap<String, usize> {
    let mut new_map = HashMap::new();
    for (idx, key) in lang_map {
        new_map.insert(key.to_string(), idx.clone());
    }
    new_map
}
