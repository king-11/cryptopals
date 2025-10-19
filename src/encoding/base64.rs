//! Base64 encoding utilities following RFC 4648.
//!
//! This module implements Base64 encoding as specified in
//! [RFC 4648 Section 4](https://datatracker.ietf.org/doc/html/rfc4648#section-4).

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
/// # Arguments
///
/// * `byte_a` - First byte (required)
/// * `byte_b` - Second byte (optional, for padding)
/// * `byte_c` - Third byte (optional, for padding)
///
/// # Returns
///
/// A vector of 2-4 Base64 characters depending on input length.
///
/// # Encoding Process
///
/// ```text
/// 3 bytes:  [AAAAAAAA] [BBBBBBBB] [CCCCCCCC]
///           ↓
/// 4 sextets: [AAAAAA][AABBBBBB][BBBBCCCC][CCCCCC]
/// ```
fn encode_triplet(byte_a: u8, byte_b: Option<u8>, byte_c: Option<u8>) -> Vec<char> {
    // First sextet: top 6 bits of byte_a
    let sextet_1 = byte_a >> 2;

    // Second sextet: bottom 2 bits of byte_a + top 4 bits of byte_b
    let sextet_2 = (byte_a & 0b0000_0011) << 4 | (byte_b.unwrap_or(0) & 0b1111_0000) >> 4;

    let mut result = vec![encode_sextet(sextet_1), encode_sextet(sextet_2)];

    // Guard clause: if only 1 byte, return 2 characters
    if byte_b.is_none() {
        return result;
    }

    // Third sextet: bottom 4 bits of byte_b + top 2 bits of byte_c
    let sextet_3 = (byte_b.unwrap() & 0b0000_1111) << 2 | (byte_c.unwrap_or(0) & 0b1100_0000) >> 6;
    result.push(encode_sextet(sextet_3));

    // Guard clause: if only 2 bytes, return 3 characters
    if byte_c.is_none() {
        return result;
    }

    // Fourth sextet: bottom 6 bits of byte_c
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

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    #[test]
    fn test_encode_empty() {
        assert_eq!(encode(b""), "");
    }

    #[test]
    fn test_encode_single_byte() {
        assert_eq!(encode(&[0xAB]), "qw==");
    }

    #[test]
    fn test_encode_two_bytes() {
        assert_eq!(encode(b"Hi"), "SGk=");
    }

    #[test]
    fn test_encode_three_bytes() {
        assert_eq!(encode(b"Man"), "TWFu");
    }

    #[test]
    fn test_encode_longer_strings() {
        assert_eq!(encode(b"Hello"), "SGVsbG8=");
        assert_eq!(
            encode(b"I'm killing your brain like a poisonous mushroom"),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn test_output_is_valid_base64() {
        let test_inputs: &[&[u8]] = &[b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"];
        let base64_regex = Regex::new(r"^[A-Za-z0-9+/]*={0,2}$").unwrap();

        for input in test_inputs {
            let encoded = encode(input);
            assert!(
                base64_regex.is_match(&encoded),
                "Output '{}' is not valid Base64",
                encoded
            );
        }
    }
}
