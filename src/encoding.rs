//! This module defines encoding operations that are used to serialize an
//! operation. Currently, the only supported operations are the insertion and
//! deletion, but there is no theoretical restriction on the kind of operation
//! that can be used.

use crate::Op;
use std::collections::HashSet;

/// The encoder is used to serialize an operation, along with the set of values
/// it operates on, into a sequence of memory words.
pub type Encoder<Value, Word, Error> = fn(Op, HashSet<Value>) -> Result<Vec<Word>, Error>;

/// The decoder is used to deserialize a sequence of memory words into a set of
/// values.
pub type Decoder<Value, Word, Error> = fn(Vec<Word>) -> Result<HashSet<Value>, Error>;

#[cfg(any(test, feature = "test-utils"))]
pub mod dummy_encoding {
    use std::hash::Hash;

    use super::*;

    /// Blocks are the smallest unit size in block mode, 16 bytes is optimized to
    /// store UUIDs.
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
}

pub mod generic_encoding {
    use std::hash::Hash;

    use super::*;

    pub fn generic_encode<const WORD_LENGTH: usize, Value: AsRef<[u8]>>(
        op: Op,
        vs: HashSet<Value>,
    ) -> Result<Vec<[u8; WORD_LENGTH]>, String> {
        let mut ws = Vec::<[u8; WORD_LENGTH]>::new();
        let mut w = [0; WORD_LENGTH];
        let mut pos = 0;

        // Returns the metadata to be written alongside the given value.
        let get_metadata = |v: &Value| {
            const MAX_VALUE_LENGTH: usize = (1 << 15) - 1;

            if v.as_ref().len() > MAX_VALUE_LENGTH {
                return Err(format!(
                    "values bigger than {} bytes cannot be encoded",
                    MAX_VALUE_LENGTH
                ));
            }

            let flag = 1;
            let len = v.as_ref().len() as u16;
            let op = if Op::Insert == op { 1 } else { 0 };

            let m = (flag << 15) | (len << 1) | op;

            Ok(m.to_be_bytes())
        };

        // Gets the length of the available space.
        let available = |pos| WORD_LENGTH - pos;

        // Writes the given bytes to the current word `w` starting at the current
        // position `pos`, overflowing into new words if the number of bytes to be
        // written is larger than the remaining space in the current word. Pushes
        // all completed word into `ws`.
        let mut write_bytes = |mut w: [u8; WORD_LENGTH], mut pos: usize, mut bytes: &[u8]| {
            if bytes.is_empty() {
                return Err("cannot encode values of length 0".to_string());
            }

            loop {
                if bytes.len() < available(pos) {
                    w[pos..pos + bytes.len()].copy_from_slice(bytes);
                    return Ok((w, pos + bytes.len()));
                } else {
                    w[pos..].copy_from_slice(&bytes[..available(pos)]);
                    ws.push(w);
                    bytes = &bytes[available(pos)..];
                    w = [0; WORD_LENGTH];
                    pos = 0;
                }
            }
        };

        for v in vs {
            let metadata = get_metadata(&v)?;
            (w, pos) = write_bytes(w, pos, &metadata)?;
            (w, pos) = write_bytes(w, pos, v.as_ref())?;
        }

        // Do not forget to push the current word if any byte were written to it.
        if 0 != pos {
            ws.push(w);
        }

        Ok(ws)
    }

    pub fn generic_decode<const WORD_LENGTH: usize, TryFromError: std::error::Error, Value>(
        ws: Vec<[u8; WORD_LENGTH]>,
    ) -> Result<HashSet<Value>, String>
    where
        for<'z> Value: Hash + PartialEq + Eq + TryFrom<&'z [u8], Error = TryFromError>,
    {
        let mut ws = ws.into_iter();
        let mut vs = HashSet::<Value>::new();
        let mut w = ws.next();
        let mut pos = 0;

        // Gets the length of the available space.
        let available = |pos| WORD_LENGTH - pos;

        // Attempts reading the next `n` bytes from the position `pos`.
        let mut read_bytes = |mut n: usize, mut pos: usize| -> (Option<Vec<u8>>, usize) {
            let mut bytes = Vec::<u8>::with_capacity(n);
            loop {
                if let Some(cur_w) = w {
                    if n <= available(pos) {
                        cur_w[pos..pos + n].iter().for_each(|b| bytes.push(*b));
                        pos += n;
                        return (Some(bytes), pos);
                    } else {
                        cur_w[pos..].iter().for_each(|b| bytes.push(*b));
                        n -= available(pos);
                        w = ws.next();
                        pos = 0;
                    }
                } else {
                    // If there is no more words and not enough bytes could be read,
                    // let the caller manage.
                    return (None, pos);
                }
            }
        };

        while let (Some(b1), new_pos) = read_bytes(1, pos) {
            if (b1[0] >> 7) == 1 {
                if let (Some(b2), new_pos) = read_bytes(1, new_pos) {
                    let m = <u16>::from_be_bytes([b1[0], b2[0]]);
                    let op = if 1 == m % 2 { Op::Insert } else { Op::Delete };
                    let n = ((m ^ (1 << 15)) >> 1) as usize; // safe conversion

                    if let (Some(bytes), new_pos) = read_bytes(n, new_pos) {
                        pos = new_pos;
                        let v = Value::try_from(&bytes).map_err(|e| e.to_string())?;
                        if Op::Insert == op {
                            vs.insert(v);
                        } else {
                            vs.remove(&v);
                        }
                    } else {
                        return Err(format!("cannot read {} bytes from the remaining words", n));
                    }
                } else {
                    return Err("cannot read second metadata byte".to_string());
                }
            } else {
                pos += available(pos);
            }
        }

        Ok(vs)
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod tests {
    use crate::{Decoder, Encoder, Op};

    use rand::{RngCore, thread_rng};
    use std::{collections::HashSet, fmt::Debug, hash::Hash};

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
    pub fn test_encoding<
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

        // Draws a random number of operations in [0,10].
        let n_ops = rng.next_u32() % 10;

        let ops = (0..n_ops)
            .map(|_| {
                // Draws a random number of values in [0,10].
                let n_vs = rng.next_u32() % 10;

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
                            let len = rng.next_u32() as usize % MAX_VALUE_LENGTH + 1;
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
        use super::dummy_encoding::*;
        for _ in 0..1_000 {
            test_encoding::<{ WORD_LENGTH - 2 }, _, _, _>(
                dummy_encode::<WORD_LENGTH, Vec<u8>>,
                dummy_decode,
            );
        }
    }

    #[test]
    fn test_better_encoding() {
        use super::generic_encoding::*;

        const WORD_LENGTH: usize = 255;
        const MAX_VALUE_LENGTH: usize = 2000;

        for _ in 0..1_000 {
            test_encoding::<MAX_VALUE_LENGTH, _, _, _>(
                generic_encode::<WORD_LENGTH, Vec<u8>>,
                generic_decode,
            );
        }
    }
}
