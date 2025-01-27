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

fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    let first_nonzero = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    &data[first_nonzero..]
}

pub const WORD_LENGTH: usize = 129;
pub fn good_encode<const WORD_LENGTH: usize, Value: AsRef<[u8]>>(
    op: Op,
    values_set: HashSet<Value>,
) -> Result<Vec<[u8; WORD_LENGTH]>, String> {
    let f = if op == Op::Insert { 1 } else { 0 };
    let mut i: usize = 0; // result word pointer
    let mut j: usize; // value input pointer
    let mut res = [0; WORD_LENGTH];

    let mut output_words: Vec<[u8; WORD_LENGTH]> = Vec::new();

    for v in values_set {
        let raw_bytes = v.as_ref();
        let value_bytes = strip_leading_zeros(raw_bytes);

        let n = value_bytes.len() as usize;
        if n > (1 << 15) {
            return Err(format!(
                "Could not convert Value to Words. Maximum Value size is 65535 bytes, got {}",
                value_bytes.len()
            ));
        }
        let coded_metadata: [u8; 2] = ((n << 1) as u16 + f).to_be_bytes(); // explicit big endian encoding

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
    encoded
        .into_iter()
        .flat_map(|arr| arr.into_iter())
        .collect()
}

pub fn good_decode<const WORD_LENGTH: usize, TryFromError: std::error::Error, Value>(
    encoded: Vec<[u8; WORD_LENGTH]>,
) -> Result<HashSet<Value>, String>
where
    for<'z> Value: Hash + Eq + TryFrom<&'z [u8], Error = TryFromError>,
{
    let input = flatten(encoded);

    let n = input.len();
    if n == 0 {
        return Ok(HashSet::new());
    }
    if n < 3 {
        return Err("Encoded data is too short ? ...".to_string());
    }
    let mut result = HashSet::new();

    let mut i = 0;

    while i < n {
        // end of data conditions, either we have a single 0 or two 0s meaning no more metadata
        if input[i] == 0 && (i == n - 1 || (i <= n - 2 && input[i + 1] == 0)) {
            break;
        }
        // -- Step 1: metadata (2 bytes)
        // Handle the edge case of having fewer than 2 bytes left
        if i + 2 >= n {
            return Err("Unexpected end of data while reading metadata".to_string());
        }

        let metadata: [u8; 2] = input[i..i + 2].try_into().unwrap(); // safe unwrap
        let f = (metadata[1] % 2) as u16; // if odd => 1 => Insert, if even => 0 => Delete
        let m = u16::from_be_bytes(metadata);

        // Check we have a perfect square
        let mut actual_size = ((m - f) >> 1) as usize; // shift right by 1 to divide by 2
        if actual_size == 0 {
            actual_size = 1;
        }
        i += 2;

        // -- Step 2: read the data
        if i + actual_size > n {
            return Err("Unexpected end of data while reading value".to_string());
        }
        let data = Vec::from(&input[i..i + actual_size]);
        i += actual_size;

        // -- Step 3: decode the operation and update the set
        let v = Value::try_from(data.as_slice())
            .map_err(|e| format!("Decoding error: {}", e.to_string()))?;
        if v == Value::try_from(&[]).unwrap() {}
        if f == 1 {
            // insert
            result.insert(v);
            // }
        } else {
            // remove
            result.remove(&v);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    // note : some tests were autogen and some were written by hand

    use super::*;
    use crate::Value;
    use std::collections::HashSet;

    #[test]
    fn test_encode_decode_simple_insert() {
        let mut values = HashSet::new();
        values.insert(Value::from(vec![1, 2, 3]));
        let encoded = good_encode::<WORD_LENGTH, Value>(Op::Insert, values.clone())
            .expect("Encoding failed.");
        let decoded = good_decode::<WORD_LENGTH, _, Value>(encoded).expect("Decoding failed.");
        assert_eq!(decoded, values);
    }

    #[test]
    fn test_encode_decode_empty_set() {
        let values: HashSet<Value> = HashSet::new();
        let encoded = good_encode::<WORD_LENGTH, Value>(Op::Insert, values.clone())
            .expect("Encoding failed.");
        let decoded = good_decode::<WORD_LENGTH, _, Value>(encoded).expect("Decoding failed.");
        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn test_encode_decode_large_values() {
        let large_value = vec![0xAB; 400]; // 400 bytes
        let mut values = HashSet::new();
        values.insert(Value::from(large_value));
        let encoded = good_encode::<WORD_LENGTH, Value>(Op::Insert, values.clone())
            .expect("Encoding large data failed.");
        let decoded =
            good_decode::<WORD_LENGTH, _, Value>(encoded).expect("Decoding large data failed.");
        assert_eq!(decoded, values);
    }

    #[test]
    fn test_encode_decode_multiple_values() {
        let mut values = HashSet::new();
        values.insert(Value::from(vec![1, 0, 0, 2]));
        values.insert(Value::from(vec![3, 4, 5, 6, 7]));
        values.insert(Value::from(vec![0, 0, 0, 10]));
        let encoded = good_encode::<WORD_LENGTH, Value>(Op::Insert, values.clone())
            .expect("Encoding multiple values failed.");

        let mut res_stripped = HashSet::new();
        for v in values.iter() {
            res_stripped.insert(Value::from(strip_leading_zeros(v.as_ref())));
        }
        let decoded = good_decode::<WORD_LENGTH, _, Value>(encoded)
            .expect("Decoding multiple values failed.");
        assert_eq!(decoded, res_stripped);
    }

    #[test]
    fn test_encode_decode_overflow_one_byte_left() {
        // Tests edge case where i == WORD_LENGTH - 1
        let mut values = HashSet::new();
        // Build a value that forces metadata to split at the last byte
        let v = vec![1; 130];
        values.insert(Value::from(v));
        let encoded = good_encode::<WORD_LENGTH, Value>(Op::Insert, values.clone())
            .expect("Encoding failed on overflow test.");
        let decoded = good_decode::<WORD_LENGTH, _, Value>(encoded)
            .expect("Decoding failed on overflow test.");
        assert_eq!(decoded, values);
    }

    #[test]
    fn testing_deletion() {
        // Tests edge case where i == WORD_LENGTH - 1
        let mut values = HashSet::new();
        // Build a value that forces metadata to split at the last byte
        let v = vec![4];
        values.insert(Value::from(v));

        let encoded: Vec<[u8; 129]> = good_encode::<WORD_LENGTH, Value>(Op::Insert, values.clone())
            .expect("Encoding failed on overflow test.");

        let encoded2: Vec<[u8; 129]> =
            good_encode::<WORD_LENGTH, Value>(Op::Delete, values.clone())
                .expect("Encoding failed on  test.");

        println!("Encoded: {:?}", encoded);
        println!("Encoded2: {:?}", encoded2);

        // let combined_encoded: Vec<[u8; 129]> = [encoded.clone(), encoded2].concat();
        let initial_data = vec![0, 3, 4, 0, 2, 4];
        let mut combined_encoded: Vec<[u8; 129]> = Vec::new();

        // Create first array with initial data, padded with zeros
        let mut first_array = [0; 129];
        first_array[..initial_data.len()].copy_from_slice(&initial_data);
        combined_encoded.push(first_array);
        // combined_encoded.insert(Value::from();
        println!("Combined: {:?}", combined_encoded);

        let decoded = good_decode::<WORD_LENGTH, _, Value>(combined_encoded)
            .expect("Decoding failed on  test.");
        assert_eq!(decoded, HashSet::new());
    }
}
