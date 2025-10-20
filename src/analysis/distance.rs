use itertools::Itertools;

use crate::crypto::xor::xor_bytes;

fn count_set_bits(byte: u8) -> usize {
    (0..8).filter(|&idx| (1 << idx) & byte != 0).count()
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> usize {
    let xored = xor_bytes(a, b);

    xored.iter().map(|&byte| count_set_bits(byte)).sum()
}

pub fn probably_key_sizes(
    bytes: &[u8],
    keys_to_consider: usize,
    chunks_to_consider: usize,
    max_key_size: usize,
) -> Vec<u32> {
    let byte_count = bytes.len();

    (1..max_key_size)
        // division with zero will cause NaN
        // that will panic given we are using total cmp
        // but this filter stops byte count zero
        .filter(|&key_size| 2 * key_size <= byte_count)
        .map(|key_size| {
            let norm_distances = bytes
                .chunks_exact(key_size)
                .take(chunks_to_consider)
                .tuples()
                .map(|(a, b)| (hamming_distance(a, b) as f32 / key_size as f32))
                .collect_vec();
            (
                key_size,
                norm_distances.iter().sum::<f32>() / norm_distances.len() as f32,
            )
        })
        .sorted_by(|(_, val1), (_, val2)| val1.total_cmp(val2))
        .map(|(key_size, _)| key_size as u32)
        .take(keys_to_consider)
        .collect_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamming_distance() {
        assert_eq!(
            12,
            hamming_distance("happy birthday".as_bytes(), "happy funnyday".as_bytes())
        );
        assert_eq!(
            0,
            hamming_distance("king-11".as_bytes(), "king-11".as_bytes())
        );
        assert_eq!(
            2,
            hamming_distance("king-12".as_bytes(), "king-11".as_bytes())
        );
        assert_eq!(
            3,
            hamming_distance("King-12".as_bytes(), "king-11".as_bytes())
        );
        assert_eq!(
            37,
            hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes())
        )
    }

    #[test]
    fn test_find_key_size() {
        let encrypted = vec![0x00, 0x63, 0x24, 0x24, 0x63, 0x24, 0x25, 0x33, 0x2D, 0x28];
        assert_eq!(vec![3, 2, 5], probably_key_sizes(&encrypted, 3, 2, 20));

        assert_eq!(
            vec![7, 2, 8],
            probably_key_sizes(
                &vec![
                    61, 10, 12, 18, 6, 23, 7, 109, 5, 24, 22, 82, 18, 1, 63, 15, 8, 65, 17, 13, 15,
                    32, 19, 5, 14, 28, 69, 91, 57, 11, 76, 21, 19, 14, 11, 35, 66
                ],
                3,
                2,
                20
            )
        );

        assert_eq!(vec![] as Vec<u32>, probably_key_sizes(&vec![], 3, 2, 20));
    }
}
