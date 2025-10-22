//! XOR cipher operations and utilities.
//!
//! This module provides functions for XOR encryption/decryption operations,
//! which are fundamental to many cryptographic challenges.

use itertools::Itertools;

use std::iter::zip;

pub fn xor_bytes(bytes_a: &[u8], bytes_b: &[u8]) -> Vec<u8> {
    zip(bytes_a, bytes_b).map(|(a, b)| a ^ b).collect()
}

/// XORs a bytes with a single byte.
pub fn single_char_xor(bytes: &[u8], char: char) -> Vec<u8> {
    let key: u8 = char as u8;
    bytes.iter().map(|&b| b ^ key).collect()
}

///XORs the provided bytes by repeating the key in a cyclic manner.
pub fn repeating_key_xor(bytes: &[u8], key: &str) -> Vec<u8> {
    zip(bytes, key.as_bytes().iter().cycle())
        .map(|(a, &b)| a ^ b)
        .collect_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex;

    #[test]
    fn test_xor_hex_strings() {
        let result = xor_bytes(
            &hex::decode("1c0111001f010100061a024b53535009181c").unwrap(),
            &hex::decode("686974207468652062756c6c277320657965").unwrap(),
        );
        assert_eq!(
            result,
            hex::decode("746865206B696420646F6E277420706C6179").unwrap()
        );
    }

    #[test]
    fn test_xor_with_char() {
        // 'A' is 0x41, XORing with itself should give 0
        let input = "4141";
        let result = single_char_xor(&hex::decode(input).unwrap(), 'A');
        assert_eq!(result, vec![0x00, 0x00]);
    }

    #[test]
    fn test_xor_is_reversible() {
        let original = hex::decode("DEADBEEF").unwrap();
        let key = 'X';

        let encrypted = single_char_xor(&original, key);
        let decrypted = single_char_xor(&encrypted, key);

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_repeating_key_xor() {
        let original = "I am alpha".as_bytes();
        let key = "ICE";

        let encrypted = repeating_key_xor(original, key);

        assert_eq!(
            vec![0x00, 0x63, 0x24, 0x24, 0x63, 0x24, 0x25, 0x33, 0x2D, 0x28],
            encrypted
        );
    }
}
