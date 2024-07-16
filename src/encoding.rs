//! This module defines encoding operations that are used to serialize an operation.
//! Currently, the only supported operations are the insertion and deletion, but there is no
//! theoretical restriction on the kind of operation that can be used.

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

#[cfg(feature = "bench")]
pub use one_byte_metadata_uid_optimized::*;

mod one_byte_metadata_uid_optimized {
    //! This module defines a compact (only one systematic metadata byte) encoding that can be used
    //! to serialize up to two different operations. It defines two *modes*:
    //! - the *block mode*, in which words are composed of multiple values encoded in an equal
    //!   number of blocks. The size of these blocks (16 bytes) has been chosen so that UIDs can
    //!   fit in a single block, thus introducing an only byte of overhead on words storing
    //!   operations on UIDs only. The size of a word has been chosen to maximize the use of this
    //!   metadata byte. Reducing the number of blocks per word would decrease the impact of
    //!   padding on partially filled words, while increasing the impact on this metadata byte on
    //!   the overall storage.
    //! - the *default mode*, in which each value written is prepended with its length, encoded
    //!   using the LEB128 format. Values may be written across words to avoid unnecessary padding.
    //!
    //!
    //! Using a single byte of metadata per word means that the overhead in block-mode is only
    //! 0.78% (without counting eventual paddings).
    //!
    //!
    //! In order to minimize the overhead, values may be sorted before being encoded in the attempt
    //! to maximize the use of the block mode (for example sorting all 16-byte values next to each
    //! other, all 32-byte ones too etc).
    //!
    //! The structure of the metadata byte is as follows:
    //! - the operation bit: designates which operation is being performed on the encoded values;
    //! - the mode bit: designates the mode in use;
    //!
    //! The meaning of the following 6 bits is mode-dependant:
    //! - in the default mode, they designate the number of values encoded in this word. Up to 64
    //!   values can be encoded in a single word, which is the limit given the available size per
    //!   word (128 bytes), and that prepending values by their LEB128 length adds a least on byte
    //!   of overhead, making the cost of storing one-byte values 2 bytes.
    //! - in the block mode, they designate the block-length (2 bits) of the values stored in this
    //!   word, and the number of such values stored in this word (3 bits).

    use super::*;

    /// Blocks are the smallest unit size in block mode, 16 bytes is optimized to store UUIDs.
    const BLOCK_LENGTH: usize = 16;

    /// The chunk length is the size of the available space in a word.
    const CHUNK_LENGTH: usize = 8 * BLOCK_LENGTH;

    pub const WORD_LENGTH: usize = 1 + CHUNK_LENGTH;

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
}

pub fn dummy_encode<const WORD_LENGTH: usize, Value: AsRef<[u8]>>(
    op: Op,
    vs: HashSet<Value>,
) -> Result<Vec<[u8; WORD_LENGTH]>, String> {
    if (u8::MAX as usize) < WORD_LENGTH {
        return Err("WORD_LENGTH too big for this encoding".to_string());
    }

    vs.into_iter()
        .map(|v| {
            let bytes = v.as_ref();
            if WORD_LENGTH - 2 < bytes.len() {
                return Err(format!(
                    "insufficient bytes in a word to fit a value of length {}",
                    bytes.len(),
                ));
            }
            let n = bytes.len() as u8;
            let mut res = [0; WORD_LENGTH];
            if op == Op::Insert {
                res[0] = 1;
            } else {
                res[0] = 0;
            }
            res[1] = n;
            res[2..bytes.len() + 2].copy_from_slice(bytes);
            Ok(res)
        })
        .collect()
}

pub fn dummy_decode<const WORD_LENGTH: usize, TryFromError: std::error::Error, Value>(
    ws: Vec<[u8; WORD_LENGTH]>,
) -> Result<HashSet<Value>, TryFromError>
where
    for<'z> Value: Hash + PartialEq + Eq + TryFrom<&'z [u8], Error = TryFromError>,
{
    let mut res = HashSet::with_capacity(ws.len());
    for w in ws {
        if !w.is_empty() {
            let n = <usize>::from(w[1]);
            let v = Value::try_from(&w[2..n + 2])?;
            if w[0] == 1 {
                res.insert(v);
            } else {
                res.remove(&v);
            }
        }
    }
    Ok(res)
}

//#[cfg(test)]
//pub mod tests {
//use cosmian_crypto_core::{
//bytes_ser_de::to_leb128_len,
//reexport::rand_core::{CryptoRngCore, SeedableRng},
//CsRng,
//};

//use super::*;

//pub fn random_uuid(rng: &mut impl CryptoRngCore) -> [u8; 16] {
//let mut res = [0; 16];
//rng.fill_bytes(&mut res);
//res
//}

//fn generate_uuids(n: usize) -> Vec<[u8; 16]> {
//let mut rng = CsRng::from_entropy();
//(0..n).map(|_| random_uuid(&mut rng)).collect()
//}

//fn random_value(rng: &mut impl CryptoRngCore, max_length: usize) -> Vec<u8> {
//let length = rng.next_u64() as usize % max_length;
//let mut res = vec![0; length];
//rng.fill_bytes(&mut res);
//res
//}

//fn generate_values(n: usize, max_length: usize) -> Vec<Vec<u8>> {
//let mut rng = CsRng::from_entropy();
//(0..n).map(|_| random_value(&mut rng, max_length)).collect()
//}

//fn test_encode_decode_uuids<TryFromError: std::error::Error>(
//encode: fn(Op, HashSet<[u8; 16]>) -> Vec<Vec<u8>>,
//decode: fn(Vec<Vec<u8>>) -> Result<HashSet<[u8; 16]>, TryFromError>,
//check_len: fn(&HashSet<[u8; 16]>) -> usize,
//) {
//for n in 0..100 {
//let values = HashSet::from_iter(generate_uuids(n));
//let words = encode(Op::Insert, values.clone());
//assert_eq!(words.len(), check_len(&values));
//let res = decode(words).unwrap();
//assert_eq!(values, res);
//}
//}

//fn test_encode_decode_variable_length_values<TryFromError: std::error::Error>(
//encode: fn(Op, HashSet<Vec<u8>>) -> Vec<Vec<u8>>,
//decode: fn(Vec<Vec<u8>>) -> Result<HashSet<Vec<u8>>, TryFromError>,
//check_len: fn(&HashSet<Vec<u8>>) -> usize,
//) {
//for max_length in [128, 2048] {
//for n in 0..100 {
//let values = HashSet::from_iter(generate_values(n, max_length));
//let words = encode(Op::Insert, values.clone());
//assert_eq!(words.len(), check_len(&values));
//let res = decode(words).unwrap();
//assert_eq!(values, res);
//}
//}
//}

//#[test]
//fn test_dummy_encoding() {
//test_encode_decode_uuids(dummy_encode, dummy_decode, |h| h.len());
//test_encode_decode_variable_length_values(dummy_encode, dummy_decode, |h| h.len());
//}

//fn test_encodings() {
//fn compute_expected_length(values: &HashSet<Vec<u8>>) -> usize {
//let total_length = values
//.iter()
//.map(Vec::len)
//.map(|l| to_leb128_len(l) + l)
//.sum::<usize>();
//(total_length as f64 / (8 * 16) as f64).ceil() as usize
//}
//}
//}
