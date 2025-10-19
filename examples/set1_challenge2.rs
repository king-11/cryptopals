//! Cryptopals Set 1, Challenge 2: Fixed XOR
//!
//! Challenge: https://cryptopals.com/sets/1/challenges/2

use cryptopals::crypto::xor::xor_hex_strings;

fn main() {
    let input_a = "1c0111001f010100061a024b53535009181c";
    let input_b = "686974207468652062756c6c277320657965";
    let expected = "746865206B696420646F6E277420706C6179";

    let result = xor_hex_strings(input_a, input_b);

    assert_eq!(result, expected);
}
