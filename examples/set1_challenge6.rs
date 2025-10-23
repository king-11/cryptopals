//! Cryptopals Set 1, Challenge 6: Break repeating-key XOR
//!
//! Challenge: https://cryptopals.com/sets/1/challenges/6

use cryptopals::analysis::distance;
use cryptopals::analysis::frequency::{
    break_single_byte_xor, calculate_frequencies, default_charset,
};
use cryptopals::crypto::xor::repeating_key_xor;
use cryptopals::encoding::base64;
use std::fs::File;
use std::io::Read as _;

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
    let mut data_file = File::open("data/set-1-6.txt").expect("challenge data file exists");
    let mut buffer = String::new();
    data_file
        .read_to_string(&mut buffer)
        .expect("valid utf8 data");

    // remove new line characters
    buffer = buffer.replace("\n", "");

    let bytes = base64::decode(&buffer).expect("valid base64 string");

    let probable_key_sizes = distance::probable_key_sizes(&bytes, 3, 4, 40);

    let result = probable_key_sizes
        .iter()
        .map(|&key| {
            let transposed = distance::transpose_byte_chunks(&bytes, key);

            transposed
                .iter()
                .map(|bytes| {
                    break_single_byte_xor(bytes, &expected_frequencies, &character_set).unwrap()
                })
                .fold((0.0, vec![]), |mut acc, (score, ch, _)| {
                    acc.1.push(ch);
                    (acc.0 + score, acc.1)
                })
        })
        // normalize sum by length of key
        .map(|(sum, chars)| (sum / chars.len() as f32, chars))
        .max_by(|(a, _), (b, _)| a.total_cmp(b))
        .unwrap();

    let key = String::from_iter(result.1.iter());
    let answer_bytes = repeating_key_xor(&bytes, &key);
    let plaintext = String::from_utf8(answer_bytes).unwrap();
    let mut actual_answer = String::new();
    File::open("data/answer-1-6.txt")
        .unwrap()
        .read_to_string(&mut actual_answer)
        .unwrap();

    assert_eq!("Terminator X: Bring the noise", key);
    println!("{}", plaintext);
    assert_eq!(
        actual_answer.replace("\n", ""),
        // remove white spaces
        plaintext.replace(" \n", "").replace("\n", "")
    );
}
