#![allow(dead_code)]

use std::{cmp::Ordering, collections::HashSet, hash::Hash};

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

pub fn dummy_encode<Value: Into<Vec<u8>>>(op: Op, vs: HashSet<Value>) -> Vec<Vec<u8>> {
    vs.into_iter()
        .map(Into::into)
        .map(|bytes| {
            if op == Op::Insert {
                [vec![1], bytes].concat()
            } else {
                [vec![0], bytes].concat()
            }
        })
        .collect()
}

pub fn dummy_decode<TryFromError: std::error::Error, Value>(
    ws: Vec<Vec<u8>>,
) -> Result<HashSet<Value>, TryFromError>
where
    for<'z> Value: Hash + PartialEq + Eq + TryFrom<&'z [u8], Error = TryFromError>,
{
    let mut res = HashSet::with_capacity(ws.len());
    for w in ws {
        if !w.is_empty() {
            let v = Value::try_from(&w[1..])?;
            if w[0] == 1 {
                res.insert(v);
            } else {
                res.remove(&v);
            }
        }
    }
    Ok(res)
}

#[cfg(test)]
pub mod tests {
    use cosmian_crypto_core::{
        bytes_ser_de::to_leb128_len,
        reexport::rand_core::{CryptoRngCore, SeedableRng},
        CsRng,
    };

    use super::*;

    pub fn random_uuid(rng: &mut impl CryptoRngCore) -> [u8; 16] {
        let mut res = [0; 16];
        rng.fill_bytes(&mut res);
        res
    }

    fn generate_uuids(n: usize) -> Vec<[u8; 16]> {
        let mut rng = CsRng::from_entropy();
        (0..n).map(|_| random_uuid(&mut rng)).collect()
    }

    fn random_value(rng: &mut impl CryptoRngCore, max_length: usize) -> Vec<u8> {
        let length = rng.next_u64() as usize % max_length;
        let mut res = vec![0; length];
        rng.fill_bytes(&mut res);
        res
    }

    fn generate_values(n: usize, max_length: usize) -> Vec<Vec<u8>> {
        let mut rng = CsRng::from_entropy();
        (0..n).map(|_| random_value(&mut rng, max_length)).collect()
    }

    fn test_encode_decode_uuids<TryFromError: std::error::Error>(
        encode: fn(Op, HashSet<[u8; 16]>) -> Vec<Vec<u8>>,
        decode: fn(Vec<Vec<u8>>) -> Result<HashSet<[u8; 16]>, TryFromError>,
        check_len: fn(&HashSet<[u8; 16]>) -> usize,
    ) {
        for n in 0..100 {
            let values = HashSet::from_iter(generate_uuids(n));
            let words = encode(Op::Insert, values.clone());
            assert_eq!(words.len(), check_len(&values));
            let res = decode(words).unwrap();
            assert_eq!(values, res);
        }
    }

    fn test_encode_decode_variable_length_values<TryFromError: std::error::Error>(
        encode: fn(Op, HashSet<Vec<u8>>) -> Vec<Vec<u8>>,
        decode: fn(Vec<Vec<u8>>) -> Result<HashSet<Vec<u8>>, TryFromError>,
        check_len: fn(&HashSet<Vec<u8>>) -> usize,
    ) {
        for max_length in [128, 2048] {
            for n in 0..100 {
                let values = HashSet::from_iter(generate_values(n, max_length));
                let words = encode(Op::Insert, values.clone());
                assert_eq!(words.len(), check_len(&values));
                let res = decode(words).unwrap();
                assert_eq!(values, res);
            }
        }
    }

    #[test]
    fn test_dummy_encoding() {
        test_encode_decode_uuids(dummy_encode, dummy_decode, |h| h.len());
        test_encode_decode_variable_length_values(dummy_encode, dummy_decode, |h| h.len());
    }

    fn test_encodings() {
        fn compute_expected_length(values: &HashSet<Vec<u8>>) -> usize {
            let total_length = values
                .iter()
                .map(Vec::len)
                .map(|l| to_leb128_len(l) + l)
                .sum::<usize>();
            (total_length as f64 / (8 * 16) as f64).ceil() as usize
        }
    }
}
