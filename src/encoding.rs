#![allow(dead_code)]

use std::{cmp::Ordering, collections::HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Insert,
    Delete,
}

pub enum Mode {
    EqBlock(usize),
    Offset(usize),
}

const BLOCK_LENGTH: usize = 16;
const CHUNK_LENGTH: usize = 8 * BLOCK_LENGTH;

fn is_admissible_eq_block_mode_value(v: &[u8]) -> bool {
    (v.len() % BLOCK_LENGTH == 0) && (v.len() < CHUNK_LENGTH)
}

fn is_eq_block_mode(_vs: &[Vec<u8>]) -> Mode {
    todo!()
}

pub(crate) fn encode<Value: Into<Vec<u8>>>(_op: Op, vs: HashSet<Value>) -> Vec<Vec<u8>> {
    let mut serialized_values = vs.into_iter().map(Into::into).collect::<Vec<_>>();
    // We sort the values in order to maximize the number of block mode chunks.
    // This is an educated guess, maybe work on a quantification.
    serialized_values.sort_by(|lhs, rhs| {
        if lhs.len() < rhs.len() {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    });

    // Use a greedy algorithm to generate chunks.
    todo!()
}

pub(crate) fn decode<Value: TryFrom<Vec<u8>>>(_ws: Vec<Vec<u8>>) -> HashSet<Value> {
    todo!()
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        bytes_ser_de::to_leb128_len,
        reexport::rand_core::{CryptoRngCore, SeedableRng},
        CsRng,
    };

    use super::*;

    #[test]
    fn test_encode_decode_uuids() {
        fn random_uuid(rng: &mut impl CryptoRngCore) -> [u8; 16] {
            let mut res = [0; 16];
            rng.fill_bytes(&mut res);
            res
        }

        fn generate_uuids(n: usize) -> Vec<[u8; 16]> {
            let mut rng = CsRng::from_entropy();
            (0..n).map(|_| random_uuid(&mut rng)).collect()
        }

        fn compute_expected_length(values: &HashSet<[u8; 16]>) -> usize {
            (values.len() as f64 / 8.0).ceil() as usize
        }

        for n in 0..100 {
            let values = HashSet::from_iter(generate_uuids(n));
            let words = encode(Op::Insert, values.clone());
            assert_eq!(words.len(), compute_expected_length(&values));
            let res = decode(words);
            assert_eq!(values, res);
        }
    }

    #[test]
    fn test_encode_decode_variable_length_values() {
        fn random_value(rng: &mut impl CryptoRngCore, max_length: usize) -> Vec<u8> {
            let length = rng.next_u64() as usize % max_length;
            let mut res = vec![0; length];
            rng.fill_bytes(&mut res);
            res
        }

        fn generate_uuids(n: usize, max_length: usize) -> Vec<Vec<u8>> {
            let mut rng = CsRng::from_entropy();
            (0..n).map(|_| random_value(&mut rng, max_length)).collect()
        }

        fn compute_expected_length(values: &HashSet<Vec<u8>>) -> usize {
            let total_length = values
                .iter()
                .map(Vec::len)
                .map(|l| to_leb128_len(l) + l)
                .sum::<usize>();
            (total_length as f64 / (8 * 16) as f64).ceil() as usize
        }

        for max_length in [128, 2048] {
            for n in 0..100 {
                let values = HashSet::from_iter(generate_uuids(n, max_length));
                let words = encode(Op::Insert, values.clone());
                assert_eq!(words.len(), compute_expected_length(&values));
                let res = decode(words);
                assert_eq!(values, res);
            }
        }
    }
}
