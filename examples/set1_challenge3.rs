//! Cryptopals Set 1, Challenge 3: Single-byte XOR cipher
//!
//! Challenge: https://cryptopals.com/sets/1/challenges/3

use cryptopals::analysis::frequency::{
    break_single_byte_xor, calculate_frequencies, default_charset,
};
use std::fs::File;
use std::io::Read;

fn main() {
    let ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    // Load baseline text for frequency analysis
    let mut baseline_file = File::open("data/time machine.txt").expect("baseline data file exists");
    let mut baseline_content = String::new();
    baseline_file
        .read_to_string(&mut baseline_content)
        .expect("can read baseline file");

    let character_set = default_charset();
    let expected_frequencies = calculate_frequencies(&character_set, &baseline_content);

    let result = break_single_byte_xor(ciphertext, &expected_frequencies, &character_set);

    assert!(result.is_some());
    let (_, plaintext) = result.unwrap();
    assert_eq!("Cooking MC's like a pound of bacon", plaintext);
}
