//! Cryptopals Set 1, Challenge 2: Fixed XOR
//!
//! Challenge: https://cryptopals.com/sets/1/challenges/2

use cryptopals::crypto::xor::xor_bytes;
use cryptopals::encoding::hex::{decode, encode};

fn main() {
    let input_a = "1c0111001f010100061a024b53535009181c";
    let input_b = "686974207468652062756c6c277320657965";

    let bytes_a = decode(input_a).expect("valid hex string");
    let bytes_b = decode(input_b).expect("valid hex string");
    let result = xor_bytes(&bytes_a, &bytes_b);

    let hex = encode(&result);
    println!("A({}) ⊕ B({}) = C({})", input_a, input_b, hex);
    assert_eq!("746865206B696420646F6E277420706C6179", hex);
}
