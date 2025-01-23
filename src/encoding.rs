//! This module defines encoding operations that are used to serialize an operation.
//! Currently, the only supported operations are the insertion and deletion, but there is no
//! theoretical restriction on the kind of operation that can be used.

#![allow(dead_code)]

use std::{collections::HashSet, hash::Hash};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Insert,
    Delete,
}

pub enum Mode {
    EqBlock(usize),
    Offset(usize),
}

/// Blocks are the smallest unit size in block mode, 16 bytes is optimized to store UUIDs.
const BLOCK_LENGTH: usize = 16;

/// The chunk length is the size of the available space in a word.
const CHUNK_LENGTH: usize = 8 * BLOCK_LENGTH;

pub fn dummy_encode<const WORD_LENGTH: usize, Value: AsRef<[u8]>>(
    op: Op,
    values_set: HashSet<Value>,
) -> Result<Vec<[u8; WORD_LENGTH]>, String> {
    if (u8::MAX as usize) < WORD_LENGTH {
        return Err("WORD_LENGTH too big for this encoding".to_string());
    }

    values_set
        .into_iter()
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
    words: Vec<[u8; WORD_LENGTH]>,
) -> Result<HashSet<Value>, String>
where
    for<'z> Value: Hash + PartialEq + Eq + TryFrom<&'z [u8], Error = TryFromError>,
{
    let mut res = HashSet::with_capacity(words.len());
    for w in words {
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

pub const WORD_LENGTH: usize = 256;

pub fn good_encode<const WORD_LENGTH: usize, Value: AsRef<[u8]>>(
    op: Op,
    values_set: HashSet<Value>,
) -> Result<Vec<[u8; WORD_LENGTH]>, String> {
    let f = if op == Op::Insert { 1 } else { 0 };
    let mut i: usize = 0; // result word pointer
    let mut j: usize = 0; // value input pointer
    let mut res = [0; WORD_LENGTH];

    // output
    let mut output_words: Vec<[u8; WORD_LENGTH]> = Vec::new();

    for v in values_set {
        let value_bytes = v.as_ref();
        let n = value_bytes.len() as usize;
        if n > (1 << 15) {
            return Err(format!(
                "Could not convert Value to Words. Maximum Value size is 65535 bytes, got {}",
                value_bytes.len()
            ));
        }
        let coded_metadata: [u8; 2] = (n as u16 * n as u16 + f).to_be_bytes(); // explicit big endian encoding

        // Step 1 : metadata

        // !!! careful, edge case if i == WORD_LENGTH - 1
        if i == WORD_LENGTH - 1 {
            // divide the metadata in two parts
            res[WORD_LENGTH - 1] = coded_metadata[0];
            output_words.push(res.clone());
            res = [0; WORD_LENGTH];
            res[0] = coded_metadata[1];
            i = 1;
        } else {
            res[i] = coded_metadata[0];
            res[i + 1] = coded_metadata[1];
            i += 2;
        }

        // Step 2 : actual data

        // case where there is still space left
        // !!!! verifiy the bound is correct
        if i + n <= WORD_LENGTH {
            res[i..i + n].copy_from_slice(value_bytes);
            i += n;
        } else {
            // there is an overflow
            let remaining_space = WORD_LENGTH - i;
            res[i..WORD_LENGTH].copy_from_slice(&value_bytes[..remaining_space]);
            output_words.push(res.clone());
            res = [0; WORD_LENGTH];

            j = remaining_space;
            while j + WORD_LENGTH <= n {
                res[..WORD_LENGTH].copy_from_slice(&value_bytes[j..j + WORD_LENGTH]);
                output_words.push(res.clone());
                res = [0; WORD_LENGTH];
                j += WORD_LENGTH;
            }
            // edge case of when the last word is exactly the size of the remaining bytes
            if j == n {
                output_words.push(res.clone());
                res = [0; WORD_LENGTH];
                i = 0;
            } else {
                res[..n - j].copy_from_slice(&value_bytes[j..n]);
                i = n - j;
            }
        };
    }
    if i > 0 {
        output_words.push(res.clone());
    }

    Ok(output_words)
}

use std::convert::TryFrom;

/// Merges a Vec<[u8; WORD_LENGTH]> into one Vec<u8>.
/// (stolen)
pub fn flatten<const WORD_LENGTH: usize>(encoded: Vec<[u8; WORD_LENGTH]>) -> Vec<u8> {
    encoded.into_iter().flat_map(|arr| arr.into_iter()).collect()
}

pub fn good_decode<const WORD_LENGTH: usize, TryFromError: std::error::Error, Value>(
    encoded: Vec<[u8; WORD_LENGTH]>,
) -> Result<HashSet<Value>, String>
where
    for<'z> Value: Hash + Eq + TryFrom<&'z [u8], Error = TryFromError>,
{   

    let input = flatten(encoded);

    let n = input.len();
    if n < 3 {
        return Err("Encoded data is too short ? ...".to_string());
    }
    let mut result = HashSet::new();

    let i = 0;

    while i < n {
        // -- Step 1: metadata (2 bytes)
        // Handle the edge case of having fewer than 2 bytes left
        if i + 2 >= n {
            return Err("Unexpected end of data while reading metadata".to_string());
        }

        let metadata = 

        let m = u16::from_be_bytes([meta_byte_0, meta_byte_1]);
        let f = (m % 2) as u8; // if odd => 1 => Insert, if even => 0 => Delete
        let squared_len = m - (f as u16);

        // Check we have a perfect square
        let n = (squared_len as f64).sqrt() as usize;
        if n * n != squared_len as usize {
            return Err(format!(
                "Invalid metadata: {} is not a perfect square plus f",
                m
            ));
        }

        // -- Step 2: read the data
        let mut data = Vec::with_capacity(n);
        for _ in 0..n {
            let next_byte = match bytes_iter.next() {
                Some(b) => b,
                None => return Err("Unexpected end of data while reading value bytes".to_string()),
            };
            data.push(next_byte);
        }

        // -- Step 3: decode the operation and update the set
        let v = Value::try_from(data.as_slice())
            .map_err(|e| format!("Decoding error: {}", e.to_string()))?;
        if f == 1 {
            // insert
            result.insert(v);
        } else {
            // remove
            result.remove(&v);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use crate::Value;
    use crate::encoding::{Op, good_decode, good_encode};
    use std::collections::HashSet;

    #[test]
    fn test_enc_dec_roundtrip() {
        let mut values: HashSet<Value> = HashSet::new();
        values.insert(Value::from(1));
        values.insert(Value::from(2));

        let encoded =
            good_encode::<256, Value>(Op::Insert, values.clone()).expect("Encoding failed");
        let decoded = good_decode::<256, _, Value>(encoded).expect("Decoding failed");

        assert_eq!(values, decoded, "Decoded set didn't match the original");
    }
}
