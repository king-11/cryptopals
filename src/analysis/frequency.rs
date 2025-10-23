//! Character frequency analysis for cryptanalysis.
//!
//! This module provides tools for analyzing text based on character frequency,
//! which is useful for breaking simple substitution ciphers like single-byte XOR.

use std::collections::{BTreeMap, HashSet};

use itertools::Itertools;

use crate::crypto::xor;

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
/// Higher scores indicate better matches. This uses the multiplicative
/// square root of expected and actual frequencies. (Bhattacharyya Distance)
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
            (expected * actual).sqrt()
        })
        .sum()
}

/// Attempts to decrypt a single-byte XOR cipher by trying all possible keys.
///
/// Tests all characters in the character set as potential XOR keys,
/// scores each decryption attempt, and returns the best match.
/// ```
pub fn break_single_byte_xor(
    bytes: &[u8],
    expected_frequency: &BTreeMap<char, f32>,
    character_set: &HashSet<char>,
) -> Option<(f32, char, String)> {
    character_set
        .iter()
        .filter_map(|&ch| {
            let decrypted_bytes = xor::single_char_xor(bytes, ch);
            match String::from_utf8(decrypted_bytes) {
                Ok(result) => Some((ch, result)),
                _ => None,
            }
        })
        .map(|(ch, plaintext)| {
            let score = score_text(&plaintext, expected_frequency, character_set);
            (score, ch, plaintext)
        })
        .max_by(|(score_a, _, _), (score_b, _, _)| score_a.total_cmp(score_b))
}

pub fn default_charset() -> HashSet<char> {
    ('a'..='z').chain('A'..='Z').chain('0'..='9').collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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

        assert!(score1 > score2);
    }
}
