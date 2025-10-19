//! Cryptopals Cryptography Challenges
//!
//! This crate contains solutions and utilities for the [Cryptopals Crypto Challenges](https://cryptopals.com/).
//!
//! The codebase is organized into three main modules:
//!
//! - [`encoding`] - Encoding/decoding utilities (hex, base64)
//! - [`crypto`] - Cryptographic operations (XOR, etc.)
//! - [`analysis`] - Cryptanalysis tools (frequency analysis, etc.)
pub mod analysis;
pub mod crypto;
pub mod encoding;

pub use encoding::hex_to_base64;
