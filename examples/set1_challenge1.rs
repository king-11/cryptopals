//! Cryptopals Set 1, Challenge 1: Convert hex to base64
//!
//! Challenge: https://cryptopals.com/sets/1/challenges/1

use cryptopals::hex_to_base64;

fn main() {
    let hex_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    let result = hex_to_base64(hex_input).unwrap();

    println!("base64({}) = {}", hex_input, result);
    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        result
    );
}
