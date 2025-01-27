//! This module defines encoding operations that are used to serialize an
//! operation. Currently, the only supported operations are the insertion and
//! deletion, but there is no theoretical restriction on the kind of operation
//! that can be used.

use std::{collections::HashSet, hash::Hash};

use crate::Op;

/// Blocks are the smallest unit size in block mode, 16 bytes is optimized to store UUIDs.
const BLOCK_LENGTH: usize = 16;

/// The chunk length is the size of the available space in a word.
const CHUNK_LENGTH: usize = 8 * BLOCK_LENGTH;

pub const WORD_LENGTH: usize = 1 + CHUNK_LENGTH;

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
) -> Result<HashSet<Value>, String>
where
    for<'z> Value: Hash + PartialEq + Eq + TryFrom<&'z [u8], Error = TryFromError>,
{
    let mut res = HashSet::with_capacity(ws.len());
    for w in ws {
        if !w.is_empty() {
            let n = <usize>::from(w[1]);
            let v = Value::try_from(&w[2..n + 2]).map_err(|e| e.to_string())?;
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
mod tests {
    use crate::{Decoder, Encoder};

    use super::*;
    use rand::{RngCore, thread_rng};
    use std::fmt::Debug;

    /// Uses fuzzing to attempt asserting that: encode ∘ decode = identity.
    ///
    /// Draw a random number of value of operation in [2,12], and for each
    /// operation draws:
    ///
    /// - a random operation in {Insert, Delete}
    ///
    /// - a random number of values in [10,100]
    ///
    /// - random values with a random number of random bytes in
    ///   [0,MAX_VALUE_LENGTH].
    ///
    /// Encode all theses operations one by one, concatenates the encoded words
    /// in chronological order, and attempt decoding the result of this
    /// operation, comparing this result against the expected set of values
    /// built from the raw decoded operations.
    fn test_encoding<
        // An upper-bound on the value length is needed for the dummy encoding.
        const MAX_VALUE_LENGTH: usize,
        // Values need to implement conversion from bytes to allow for a uniform
        // random generation. This bound could be changed to `Serializable` or
        // `TryFrom`.
        Value: Hash + From<Vec<u8>> + Clone + PartialEq + Eq + Debug,
        Word,
        EncodingError: Debug,
    >(
        encode: Encoder<Value, Word, EncodingError>,
        decode: Decoder<Value, Word, EncodingError>,
    ) {
        let mut rng = thread_rng();

        // Draws a random number of operations in [2,12].
        let n_ops = rng.next_u32() % 10 + 2;

        let ops = (0..n_ops)
            .map(|_| {
                // Draws a random number of values in [10,100].
                let n_vs = rng.next_u32() % 90 + 10;

                (
                    // draws a random operation
                    if rng.next_u32() % 2 == 1 {
                        Op::Insert
                    } else {
                        Op::Delete
                    },
                    // draws random values
                    (0..n_vs)
                        .map(|_| {
                            let len = rng.next_u32() as usize % MAX_VALUE_LENGTH;
                            let mut bytes = vec![0; len];
                            rng.fill_bytes(&mut bytes);
                            Value::from(bytes)
                        })
                        .collect::<HashSet<_>>(),
                )
            })
            .collect::<Vec<_>>();

        let ws = ops
            .iter()
            .cloned()
            .flat_map(|(op, vs)| encode(op, vs).unwrap())
            .collect::<Vec<Word>>();

        let res = decode(ws).unwrap();

        // Now, build the expected result.
        let expected_res = ops.into_iter().fold(HashSet::new(), |h, (op, vs)| {
            if Op::Insert == op {
                vs.into_iter().fold(h, |mut h, v| {
                    h.insert(v);
                    h
                })
            } else {
                vs.into_iter().fold(h, |mut h, v| {
                    h.remove(&v);
                    h
                })
            }
        });

        assert_eq!(res, expected_res);
    }

    #[test]
    fn test_dummy_encoding() {
        test_encoding::<{ WORD_LENGTH - 2 }, _, _, _>(
            dummy_encode::<WORD_LENGTH, Vec<u8>>,
            dummy_decode,
        );
    }
}
