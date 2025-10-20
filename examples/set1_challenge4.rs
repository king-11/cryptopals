//! Cryptopals Set 1, Challenge 4: Detect single-character XOR
//!
//! Challenge: https://cryptopals.com/sets/1/challenges/4

use cryptopals::analysis::frequency::{
    break_single_byte_xor, calculate_frequencies, default_charset,
};
use cryptopals::encoding::hex;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};

fn main() {
    // Load baseline text for frequency analysis
    let mut baseline_file = File::open("data/time machine.txt").expect("baseline data file exists");
    let mut baseline_content = String::new();
    baseline_file
        .read_to_string(&mut baseline_content)
        .expect("can read baseline file");

    let character_set = default_charset();
    let expected_frequencies = calculate_frequencies(&character_set, &baseline_content);

    // Load challenge data
    let data_file = File::open("data/set-1-4.txt").expect("challenge data file exists");
    let buffered_reader = BufReader::new(data_file);

    let mut scores = BTreeMap::new();
    for line in buffered_reader.lines() {
        let hex_line = line.expect("file contains valid UTF-8");
        let bytes = hex::decode(&hex_line);

        if let Some((score, plaintext)) =
            break_single_byte_xor(&bytes, &expected_frequencies, &character_set)
        {
            scores.insert(plaintext, score);
        }
    }

    let best_match = scores
        .iter()
        .min_by(|(_, score_a), (_, score_b)| {
            score_a
                .partial_cmp(score_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(text, _)| text)
        .expect("found at least one match");

    assert_eq!("Now that the party is jumping\n", best_match);
}
