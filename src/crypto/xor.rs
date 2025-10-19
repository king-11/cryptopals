//! XOR cipher operations and utilities.
//!
//! This module provides functions for XOR encryption/decryption operations,
//! which are fundamental to many cryptographic challenges.

use itertools::Itertools;

use crate::encoding::hex;
use std::iter::zip;

/// XORs two hexadecimal strings together.
///
/// Takes two hex-encoded strings of equal length and XORs their byte values.
/// The result is returned as a hex-encoded string.
///
/// # Examples
///
/// ```
/// use cryptopals::crypto::xor::xor_hex_strings;
///
/// let result = xor_hex_strings(
///     "1c0111001f010100061a024b53535009181c",
///     "686974207468652062756c6c277320657965"
/// );
/// assert_eq!(result, "746865206B696420646F6E277420706C6179");
/// ```
///
/// # Panics
///
/// Panics if either input contains invalid hex characters.
pub fn xor_hex_strings(hex_a: &str, hex_b: &str) -> String {
    let bytes_a = hex::decode(hex_a);
    let bytes_b = hex::decode(hex_b);

    let xored_bytes: Vec<u8> = zip(bytes_a, bytes_b).map(|(a, b)| a ^ b).collect();

    hex::encode(&xored_bytes)
}

/// XORs a hex-encoded string with a single character.
///
/// Each byte of the decoded hex string is XORed with the ASCII value
/// of the provided character.
pub fn xor_with_byte(hex_string: &str, byte: u8) -> Vec<u8> {
    let bytes = hex::decode(hex_string);
    bytes.iter().map(|&b| b ^ byte).collect()
}

/// XORs a hex-encoded string with a single character (char version).
///
/// Convenience function that accepts a char instead of a byte.
///
/// # Examples
///
/// ```
/// use cryptopals::crypto::xor::xor_with_char;
///
/// let result = xor_with_char("48656c6c6f", 'A');
/// ```
pub fn xor_with_char(hex_string: &str, ch: char) -> Vec<u8> {
    xor_with_byte(hex_string, ch as u8)
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

    #[test]
    fn test_xor_hex_strings() {
        let result = xor_hex_strings(
            "1c0111001f010100061a024b53535009181c",
            "686974207468652062756c6c277320657965",
        );
        assert_eq!(result, "746865206B696420646F6E277420706C6179");
    }

    #[test]
    fn test_xor_with_byte() {
        let result = xor_with_byte("FFFF", 0xFF);
        assert_eq!(result, vec![0x00, 0x00]);

        let result = xor_with_byte("0000", 0x00);
        assert_eq!(result, vec![0x00, 0x00]);
    }

    #[test]
    fn test_xor_with_char() {
        // 'A' is 0x41, XORing with itself should give 0
        let input = "4141";
        let result = xor_with_char(input, 'A');
        assert_eq!(result, vec![0x00, 0x00]);
    }

    #[test]
    fn test_xor_is_reversible() {
        let original = "DEADBEEF";
        let key = 'X';

        let encrypted = xor_with_char(original, key);
        let encrypted_hex = hex::encode(&encrypted);
        let decrypted = xor_with_char(&encrypted_hex, key);
        let decrypted_hex = hex::encode(&decrypted);

        assert_eq!(original, decrypted_hex);
    }

    #[test]
    fn test_repeating_key_xor() {
        let original = "I am alpha".as_bytes();
        let key = "ICE";

        let encrypted = repeating_key_xor(original, key);

        println!("{:?}", key.as_bytes());
        println!("{:?}", original);
        assert_eq!(
            vec![0x00, 0x63, 0x24, 0x24, 0x63, 0x24, 0x25, 0x33, 0x2D, 0x28],
            encrypted
        );
    }
}
