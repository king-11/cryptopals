//! Hexadecimal encoding and decoding utilities.
//!
//! This module provides functions for converting between hexadecimal strings
//! and byte arrays, with proper validation.

use itertools::Itertools;

/// Validates if a string is a valid hexadecimal encoding.
///
/// A valid hex string must:
/// - Have even length (each byte is represented by 2 hex digits)
/// - Contain only ASCII hexadecimal characters (0-9, A-F, a-f)
///
/// # Examples
///
/// ```
/// use cryptopals::encoding::hex::is_valid;
///
/// assert!(is_valid("DEADBEEF"));
/// assert!(!is_valid("INVALID"));
/// assert!(!is_valid("ABC")); // odd length
/// ```
pub fn is_valid(hex: &str) -> bool {
    (hex.len() & 1) == 0 && hex.chars().all(|char| char.is_ascii_hexdigit())
}

/// Decodes a hexadecimal string into a vector of bytes.
///
/// Each pair of hex characters is converted to a single byte.
/// If the input has odd length, the last character is treated as having
/// a trailing zero (though this should be validated with `is_valid` first).
///
/// # Examples
///
/// ```
/// use cryptopals::encoding::hex::decode;
///
/// let bytes = decode("48656c6c6f");
/// assert_eq!(bytes, vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]);
/// ```
///
/// # Panics
///
/// Panics if the string contains non-hexadecimal characters.
pub fn decode(hex: &str) -> Vec<u8> {
    hex.chars()
        .map(|char| char.to_digit(16).unwrap() as u8)
        .batching(|it| match it.next() {
            None => None,
            Some(x) => match it.next() {
                Some(y) => Some((x, y)),
                None => Some((x, 0)),
            },
        })
        .map(|(a, b)| a << 4 | b)
        .collect_vec()
}

/// Encodes a vector of bytes as a hexadecimal string.
///
/// Each byte is converted to two hexadecimal characters.
/// The output is uppercase.
///
/// # Examples
///
/// ```
/// use cryptopals::encoding::hex::encode;
///
/// let hex = encode(&vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]);
/// assert_eq!(hex, "48656C6C6F");
/// ```
pub fn encode(bytes: &[u8]) -> String {
    let chars = bytes
        .iter()
        .flat_map(|&byte| {
            // Split byte into two 4-bit nibbles
            let high = byte >> 4;
            let low = byte & 0b1111;
            vec![high, low]
        })
        .map(|digit| char::from_digit(digit as u32, 16).expect("nibble is always < 16"));

    String::from_iter(chars).to_uppercase()
}

/// Convert regular text to hex encoded text
pub fn encode_text(text: &str) -> String {
    let bytes = text.as_bytes();

    encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn valid_hex_roundtrip(s in "([A-Fa-f0-9]{2})+") {
            let decoded = decode(&s);
            let encoded = encode(&decoded);
            assert_eq!(s.to_uppercase(), encoded);
        }
    }

    #[test]
    fn test_validation() {
        assert!(is_valid("DEADBEEF"));
        assert!(is_valid("abcd1234"));
        assert!(is_valid(""));

        // invalid character
        assert!(!is_valid("ABCD123I"));
        // odd length
        assert!(!is_valid("ABCD12345"));
        // invalid hex
        assert!(!is_valid("GG"));
    }

    #[test]
    fn test_encode_decode() {
        let bytes = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f];
        let hex = encode(&bytes);
        assert_eq!(hex, "48656C6C6F");

        let decoded = decode("48656c6c6f");
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_decode_uppercase_and_lowercase() {
        let upper = decode("DEADBEEF");
        let lower = decode("deadbeef");
        assert_eq!(upper, lower);
    }

    #[test]
    fn test_text_encode() {
        assert_eq!(
            "4920616d20616c70686120313121",
            encode_text("I am alpha 11!").to_lowercase()
        )
    }
}
