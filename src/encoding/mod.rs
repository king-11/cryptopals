//! Encoding and decoding utilities.
//!
//! This module provides conversions between different data representations,
//! including hexadecimal and Base64 encoding.

pub mod base64;
pub mod hex;

use std::io::{Error, ErrorKind};

/// Converts a hexadecimal string to Base64 encoding.
///
/// This is a convenience function that combines hex decoding and Base64 encoding.
///
/// # Examples
///
/// ```
/// use cryptopals::encoding::hex_to_base64;
///
/// let result = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
/// assert_eq!(result, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
/// ```
///
/// # Errors
///
/// Returns an error if the input is not valid hexadecimal.
pub fn hex_to_base64(hex_string: &str) -> Result<String, Error> {
    if !hex::is_valid(hex_string) {
        return Err(Error::new(ErrorKind::InvalidInput, "invalid hex encoding"));
    }

    let bytes = hex::decode(hex_string);
    Ok(base64::encode(&bytes))
}
