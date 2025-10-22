//! Base64 encoding utilities following RFC 4648.
//!
//! This module implements Base64 encoding as specified in
//! [RFC 4648 Section 4](https://datatracker.ietf.org/doc/html/rfc4648#section-4).

use crate::encoding::error::{Encoding, ParsingDirection, ParsingError};
use itertools::Itertools;
use std::sync::LazyLock;

/// Base64 character set: A-Z, a-z, 0-9, +, /
static BASE64_CHARSET: LazyLock<[char; 64]> = LazyLock::new(|| {
    ('A'..='Z')
        .chain('a'..='z')
        .chain('0'..='9')
        .chain(['+', '/'])
        .collect::<Vec<char>>()
        .try_into()
        .expect("total count of characters is 64")
});

/// Converts a 6-bit value to its Base64 character representation.
///
/// # Panics
///
/// Panics if the value is greater than 63 (not representable in 6 bits).
#[inline]
fn encode_sextet(value: u8) -> char {
    debug_assert!(value < 64, "value must be 6-bit (< 64)");
    BASE64_CHARSET[value as usize]
}

/// Encodes 1-3 bytes into Base64 characters.
///
/// According to RFC 4648, Base64 encoding takes groups of 3 bytes (24 bits)
/// and splits them into 4 groups of 6 bits, each encoded as a character.
///
/// # Encoding Process
///
/// ```text
/// 3 bytes:  [AAAAAAAA] [BBBBBBBB] [CCCCCCCC]
///           ↓
/// 4 sextets: [AAAAAA][AABBBBBB][BBBBCCCC][CCCCCC]
/// ```
fn encode_triplet(byte_a: u8, byte_b: Option<u8>, byte_c: Option<u8>) -> Vec<char> {
    let sextet_1 = byte_a >> 2;

    let sextet_2 = (byte_a & 0b0000_0011) << 4 | (byte_b.unwrap_or(0) & 0b1111_0000) >> 4;

    let mut result = vec![encode_sextet(sextet_1), encode_sextet(sextet_2)];

    if byte_b.is_none() {
        return result;
    }

    let sextet_3 = (byte_b.unwrap() & 0b0000_1111) << 2 | (byte_c.unwrap_or(0) & 0b1100_0000) >> 6;
    result.push(encode_sextet(sextet_3));

    if byte_c.is_none() {
        return result;
    }

    let sextet_4 = byte_c.unwrap() & 0b0011_1111;
    result.push(encode_sextet(sextet_4));

    result
}

/// Encodes a byte slice into a Base64 string.
///
/// Implements standard Base64 encoding with padding ('=') as per RFC 4648.
///
/// # Examples
///
/// ```
/// use cryptopals::encoding::base64::encode;
///
/// let encoded = encode(b"Hello");
/// assert_eq!(encoded, "SGVsbG8=");
///
/// let encoded = encode(b"Hi");
/// assert_eq!(encoded, "SGk=");
/// ```
pub fn encode(bytes: &[u8]) -> String {
    // Process complete triplets (groups of 3 bytes)
    let complete_triplets: String = bytes
        .chunks_exact(3)
        .flat_map(|chunk| encode_triplet(chunk[0], Some(chunk[1]), Some(chunk[2])))
        .collect();

    // Handle remaining bytes (0, 1, or 2 bytes)
    let remainder = bytes.len() % 3;
    let padding = match remainder {
        0 => String::new(),
        1 => {
            // 1 byte → 2 Base64 chars + 2 padding chars
            let mut chars = encode_triplet(bytes[bytes.len() - 1], None, None);
            chars.extend(['=', '=']);
            chars.into_iter().collect()
        }
        2 => {
            // 2 bytes → 3 Base64 chars + 1 padding char
            let mut chars =
                encode_triplet(bytes[bytes.len() - 2], Some(bytes[bytes.len() - 1]), None);
            chars.push('=');
            chars.into_iter().collect()
        }
        _ => unreachable!(),
    };

    format!("{}{}", complete_triplets, padding)
}

/// Converts a base64 representation to its u6 value, '=' is returned as value 65
#[inline]
fn decode_sextet(value: char) -> u8 {
    if value == '=' {
        return 65;
    }

    BASE64_CHARSET
        .iter()
        .find_position(|&ch| ch.eq(&value))
        .map(|(idx, _)| idx as u8)
        .expect("value is a base64 character")
}

fn decode_quatret(encoded: &[char; 4]) -> Result<Vec<u8>, ParsingError> {
    let chars: [Option<u8>; 4] = encoded
        .iter()
        .map(|&char| {
            if char.eq(&'=') {
                None
            } else {
                Some(decode_sextet(char))
            }
        })
        .collect::<Vec<Option<u8>>>()
        .try_into()
        .expect("no filtering was done");

    if chars[0].is_none() && chars[1].is_none() {
        return Err(ParsingError::from_string(
            ParsingDirection::Decoding,
            Encoding::Base64,
            String::from_iter(encoded.iter()),
        ));
    }

    let (first_sextet, second_sextet) = (chars[0].unwrap(), chars[1].unwrap());

    let first_byte = first_sextet << 2 | (second_sextet & 0b00110000) >> 4;
    if chars[2].is_none() {
        return Ok(vec![first_byte]);
    }

    let third_sextet = chars[2].unwrap();
    let second_byte = (second_sextet & 0b00001111) << 4 | (third_sextet & 0b111100) >> 2;
    if chars[3].is_none() {
        return Ok(vec![first_byte, second_byte]);
    }

    let fourth_sextet = chars[3].unwrap();
    let third_byte = (third_sextet & 0b11) << 6 | fourth_sextet;
    Ok(vec![first_byte, second_byte, third_byte])
}

pub fn decode(encoded: &str) -> Result<Vec<u8>, ParsingError> {
    if encoded.len() % 4 != 0 {
        return Err(ParsingError::from_string(
            ParsingDirection::Decoding,
            Encoding::Base64,
            encoded.to_owned(),
        ));
    }

    encoded
        .chars()
        .chunks(4)
        .into_iter()
        .try_fold(Vec::new(), |mut acc, chunk| {
            let decoded = decode_quatret(&chunk.collect_array::<4>().unwrap())?;
            acc.extend(decoded);
            Ok(acc)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_empty() {
        assert_eq!(encode(b""), "");
        assert_eq!(decode("").unwrap(), b"");
    }

    #[test]
    fn test_encode_single_byte() {
        assert_eq!(encode(&[0xAB]), "qw==");
        assert_eq!(decode("qw==").unwrap(), [0xAB]);
    }

    #[test]
    fn test_encode_two_bytes() {
        assert_eq!(encode(b"Hi"), "SGk=");
        assert_eq!(decode("SGk=").unwrap(), b"Hi");
    }

    #[test]
    fn test_encode_three_bytes() {
        assert_eq!(encode(b"Man"), "TWFu");
        assert_eq!(decode("TWFu").unwrap(), b"Man");
    }

    #[test]
    fn test_encode_longer_strings() {
        assert_eq!(encode(b"Hello"), "SGVsbG8=");
        assert_eq!(decode("SGVsbG8=").unwrap(), b"Hello");
        assert_eq!(
            encode(b"I'm killing your brain like a poisonous mushroom"),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
        assert_eq!(
            decode("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t").unwrap(),
            b"I'm killing your brain like a poisonous mushroom"
        );
    }
}
