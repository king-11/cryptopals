//! Character frequency analysis for cryptanalysis.
//!
//! This module provides tools for analyzing text based on character frequency,
//! which is useful for breaking simple substitution ciphers like single-byte XOR.

use std::collections::{BTreeMap, HashSet};

use itertools::Itertools;

use crate::crypto::xor;

/// Converts a byte slice to a UTF-8 string, filtering out invalid characters.
///
/// This is useful when you have potentially noisy data and want to extract
/// readable text from it.
///
/// # Examples
///
/// ```
/// use cryptopals::analysis::frequency::bytes_to_string;
///
/// let bytes = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello"
/// let text = bytes_to_string(&bytes);
/// assert_eq!(text, "Hello");
/// ```
pub fn bytes_to_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .filter_map(|&byte| char::from_u32(byte as u32))
        .collect()
}

/// Calculates character frequencies for a given text.
///
/// Returns a map of character → frequency (as a fraction of total characters).
/// Only characters in the provided character set are counted.
///
/// # Examples
///
/// ```
/// use std::collections::HashSet;
/// use cryptopals::analysis::frequency::calculate_frequencies;
///
/// let charset: HashSet<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
/// let freqs = calculate_frequencies(&charset, "hello world");
/// // 'l' appears 3 times out of 10 letters → frequency ≈ 0.3
/// ```
pub fn calculate_frequencies(character_set: &HashSet<char>, text: &str) -> BTreeMap<char, f32> {
    let total_count = text.chars().count() as f32;

    if total_count == 0.0 {
        return BTreeMap::new();
    }

    text.chars()
        .filter(|ch| character_set.contains(ch))
        .into_group_map_by(|&ch| ch)
        .iter()
        .map(|(&ch, occurrences)| (ch, occurrences.len() as f32 / total_count))
        .collect()
}

/// Scores text based on how well it matches expected character frequencies.
///
/// Lower scores indicate better matches. This uses the sum of absolute
/// differences between expected and actual frequencies.
pub fn score_text(
    text: &str,
    expected_frequency: &BTreeMap<char, f32>,
    character_set: &HashSet<char>,
) -> f32 {
    let actual_frequency = calculate_frequencies(character_set, text);

    character_set
        .iter()
        .map(|&ch| {
            let expected = expected_frequency.get(&ch).unwrap_or(&0.0);
            let actual = actual_frequency.get(&ch).unwrap_or(&0.0);
            (expected - actual).abs()
        })
        .sum()
}

/// Attempts to decrypt a single-byte XOR cipher by trying all possible keys.
///
/// Tests all characters in the character set as potential XOR keys,
/// scores each decryption attempt, and returns the best match.
/// ```
pub fn break_single_byte_xor(
    hex_ciphertext: &str,
    expected_frequency: &BTreeMap<char, f32>,
    character_set: &HashSet<char>,
) -> Option<(f32, String)> {
    character_set
        .iter()
        .map(|&ch| {
            let decrypted_bytes = xor::xor_with_char(hex_ciphertext, ch);
            bytes_to_string(&decrypted_bytes)
        })
        .map(|plaintext| {
            let score = score_text(&plaintext, expected_frequency, character_set);
            (score, plaintext)
        })
        .min_by(|(score_a, _), (score_b, _)| {
            score_a
                .partial_cmp(score_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

pub fn default_charset() -> HashSet<char> {
    ('a'..='z').chain('A'..='Z').chain('0'..='9').collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_string() {
        let bytes = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f];
        assert_eq!(bytes_to_string(&bytes), "Hello");

        let noisy_bytes = vec![0x48, 0x69, 0xFF, 0x21]; // "Hi" + invalid + "!"
        let result = bytes_to_string(&noisy_bytes);

        assert!(result.contains('H'));
        assert!(result.contains('i'));
    }

    #[test]
    fn test_calculate_frequencies() {
        let charset: HashSet<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
        let freqs = calculate_frequencies(&charset, "hello");

        assert_eq!(freqs.get(&'h'), Some(&0.2));
        assert_eq!(freqs.get(&'l'), Some(&0.4));
        assert_eq!(freqs.get(&'z'), None);
    }

    #[test]
    fn test_score_text() {
        let charset = default_charset();
        let mut expected_freq = BTreeMap::new();
        expected_freq.insert('a', 0.5);
        expected_freq.insert('b', 0.5);

        let score1 = score_text("ab", &expected_freq, &charset);
        let score2 = score_text("aaaa", &expected_freq, &charset);

        assert!(score1 < score2);
    }
}
