use std::{
    io::{Error, ErrorKind::InvalidInput},
    sync::LazyLock,
    vec,
};

use itertools::Itertools;

fn is_hex_valid(hex: &str) -> bool {
    (hex.len() & 1) == 0 && hex.is_ascii() && hex.chars().all(|char| char.is_ascii_hexdigit())
}

fn hex_to_u8(hex: &str) -> Vec<u8> {
    hex.chars()
        .map(|char| char.to_digit(16).unwrap() as u8)
        .batching(|it| match it.next() {
            None => None,
            Some(x) => match it.next() {
                Some(y) => Some((x, y)),
                None => Some((x, 0)),
            },
        })
        .map(|(a, b)| a << 4 | b)
        .collect_vec()
}

static BASE64_VALUES: LazyLock<[char; 64]> = LazyLock::new(|| {
    ('A'..='Z')
        .chain('a'..='z')
        .chain('0'..='9')
        .chain(vec!['+', '/'].into_iter())
        .collect::<Vec<char>>()
        .try_into()
        .expect("total count of characters is 64")
});

fn u6_to_base64_encode(idx: u8) -> Result<char, Error> {
    if idx > 64 {
        return Err(Error::new(InvalidInput, "value larger than base64"));
    }

    Ok(*BASE64_VALUES.get(idx as usize).unwrap())
}

/// https://datatracker.ietf.org/doc/html/rfc4648#section-4
pub fn bytes_to_base64_encode(ba: u8, bb: Option<u8>, bc: Option<u8>) -> Vec<char> {
    let idx1 = ba >> 2;
    let idx2 = (ba & 0b00000011) << 4 | (bb.unwrap_or(0) & 0b11110000) >> 4;
    let mut vectors = vec![
        u6_to_base64_encode(idx1).unwrap(),
        u6_to_base64_encode(idx2).unwrap(),
    ];

    if bb.is_none() && bc.is_none() {
        return vectors;
    }

    let idx3 = (bb.unwrap() & 0b00001111) << 2 | (bc.unwrap_or(0) & 0b11000000) >> 6;
    vectors.push(u6_to_base64_encode(idx3).unwrap());
    if bc.is_none() {
        return vectors;
    }

    let idx4 = bc.unwrap() & 0b00111111;
    vectors.push(u6_to_base64_encode(idx4).unwrap());

    return vectors;
}

/// https://datatracker.ietf.org/doc/html/rfc4648#section-4
pub fn binary_to_base64(binary: &[u8]) -> String {
    let chunks = binary
        .iter()
        .tuples::<(_, _, _)>()
        .map(|(&a, &b, &c)| bytes_to_base64_encode(a, Some(b), Some(c)))
        .flatten()
        .collect_vec();

    let binary_val_count = binary.len();
    let last_chunk = match binary_val_count % 3 {
        0 => vec![],
        1 => vec![
            bytes_to_base64_encode(*binary.get(binary_val_count - 1).unwrap(), None, None).to_vec(),
            vec!['=', '='],
        ]
        .concat(),
        2 => vec![
            bytes_to_base64_encode(
                *binary.get(binary_val_count - 2).unwrap(),
                Some(*binary.get(binary_val_count - 1).unwrap()),
                None,
            )
            .to_vec(),
            vec!['='],
        ]
        .concat(),
        _ => unimplemented!(),
    };

    let mut base64 = String::from_iter(chunks);
    base64.extend(last_chunk);
    return base64;
}

pub fn hex_to_base64(hex: &str) -> Result<String, Error> {
    if !is_hex_valid(hex) {
        return Err(Error::new(InvalidInput, "invalid hex encoding"));
    }

    let binary = hex_to_u8(hex);

    Ok(binary_to_base64(&binary))
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use super::*;

    #[test]
    fn test_invalid_input() {
        let input_hex = String::from("ABCD1234I");

        let result = hex_to_base64(&input_hex);

        assert!(result.is_err());
        assert_eq!(
            ErrorKind::InvalidInput,
            hex_to_base64(&input_hex).err().unwrap().kind()
        )
    }

    #[test]
    fn test_hex_to_base64() {
        assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
          hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap());
        assert_eq!("qw==", hex_to_base64("AB").unwrap());
        assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb28=",
          hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f").unwrap());
    }
}
