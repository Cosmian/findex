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

use std::fmt::Debug;

pub const WORD_LENGTH: usize = 129;
pub fn good_encode<const WORD_LENGTH: usize, Value: Clone + Debug + AsRef<[u8]>>(
    op: Op,
    values_set: HashSet<Value>,
) -> Result<Vec<[u8; WORD_LENGTH]>, String> {
    println!("op: {:?}", op);
    println!("values_set: {:?}", values_set.clone());

    let f = if op == Op::Insert { 1 } else { 0 };

    let mut i: usize = 0; // result word pointer - TODO change this name
    let mut j: usize; // value input pointer - TODO change

    let mut current_word = [0; WORD_LENGTH];

    let mut output_words: Vec<[u8; WORD_LENGTH]> = Vec::new();

    for v in values_set {
        let value_bytes = v.as_ref();
        let value_bytes_length = value_bytes.len();
        if value_bytes_length > ((1 << 16) - 1) {
            return Err(format!(
                "Could not convert Value to Words. Maximum Value size is 65535 bytes, got {}",
                value_bytes.len()
            ));
        }

        let coded_metadata: [u8; 2] = ((value_bytes_length << 1) as u16 + f).to_be_bytes(); // explicit big endian encoding

        // Step 1 : inserting the metadata, which is constituted from the operator and the byte size of the data
        // !!! careful, edge case if i == WORD_LENGTH - 1

        if i == WORD_LENGTH - 1 {
            // divide the metadata in two parts
            current_word[WORD_LENGTH - 1] = coded_metadata[0];
            output_words.push(current_word);

            current_word = [0; WORD_LENGTH];
            current_word[0] = coded_metadata[1];

            i = 1;
        } else if i == WORD_LENGTH {
            // another edge case, if there is no more bytes left
            output_words.push(current_word);

            i = 0;
            current_word = [0; WORD_LENGTH];

            current_word[i] = coded_metadata[0];
            current_word[i + 1] = coded_metadata[1];
            i += 2;
        } else {
            // .copy_from_slice(&coded_metadata); :: TODO
            current_word[i] = coded_metadata[0];
            current_word[i + 1] = coded_metadata[1];
            i += 2;
        }

        // Step 2 : actual data

        // case where there is still space left
        // !!!! verifiy the bound is correct

        if i + value_bytes_length <= WORD_LENGTH {
            // TODO  : comment this
            current_word[i..i + value_bytes_length].copy_from_slice(value_bytes);
            i += value_bytes_length;
        } else {
            // there is an overflow
            let remaining_space = WORD_LENGTH - i;
            current_word[i..WORD_LENGTH].copy_from_slice(&value_bytes[..remaining_space]);

            output_words.push(current_word);
            current_word = [0; WORD_LENGTH];
            // i = ?
            // 00000000|00000000000000000000|0000000000000000000|00000000000
            j = remaining_space;
            while j + WORD_LENGTH <= value_bytes_length {
                // changer ça par la taille de la slice - qui reste - est plus grad qune la taille de un mot
                /// recal
                current_word[..WORD_LENGTH].copy_from_slice(&value_bytes[j..j + WORD_LENGTH]); // recal 

                output_words.push(current_word);
                current_word = [0; WORD_LENGTH];

                j += WORD_LENGTH;
            }
            // edge case of when the last word is exactly the size of the remaining bytes
            if j == value_bytes_length {
                output_words.push(current_word);
                current_word = [0; WORD_LENGTH];
                i = 0;
            } else {
                current_word[..value_bytes_length - j]
                    .copy_from_slice(&value_bytes[j..value_bytes_length]);
                i = value_bytes_length - j;
            }
        };
    }
    if i > 0 {
        output_words.push(current_word);
    }

    println!("output_words: {:?}", output_words);

    Ok(output_words)
    /*
    cas particulier : interdit de code une valeu de taille 0
     */
}

use std::convert::TryFrom;

pub fn flatten<const WORD_LENGTH: usize>(encoded: Vec<[u8; WORD_LENGTH]>) -> Vec<u8> {
    encoded
        .into_iter()
        .flat_map(|arr| arr.into_iter())
        .collect()
}

pub fn good_decode<const WORD_LENGTH: usize, TryFromError: std::error::Error, Value>(
    words: Vec<[u8; WORD_LENGTH]>,
) -> Result<HashSet<Value>, String>
where
    for<'z> Value: Clone + Hash + Eq + TryFrom<&'z [u8], Error = TryFromError> + Debug,
{
    let input = flatten(words.clone());
    println!("DECODE_OPERATION | words: {:?}", words);

    let n = input.len();
    if n != WORD_LENGTH * words.len() {
        panic!("That is wrong");
    }
    if n == 0 {
        return Ok(HashSet::new()); // a voir 
    }
    if n < 3 {
        return Err("Encoded data is too short ? ...".to_string());
    }
    let mut result = HashSet::new();

    let mut i = 0;

    while i < n {
        // println!("DECODE_OPERATION | i: {:?}", i);
        // end of data conditions, either we have a single 0 or two 0s meaning no more metadata
        if input[i] == 0 && (i == n - 1 || (i <= n - 2 && input[i + 1] == 0)) {
            println!("DECODE_OPERATION | BREAKING: {:?}", &input[i..]);
            i += 1;
            // TODO : soit il reste moins de 2 octets OU il reste 2 octets et ils sont tous les deux à 0
            // input.as_slice[..n]
            continue;
        }
        // -- Step 1: metadata (2 bytes)

        let metadata: [u8; 2] = input[i..i + 2].try_into().unwrap(); // safe unwrap
        let f = (metadata[1] % 2) as u16; // if odd => 1 => Insert, if even => 0 => Delete
        let len = (u16::from_be_bytes(metadata) >> 1) as usize; // shift right by 1 to divide by 2
        i += 2;

        // -- Step 2: read the data
        if i + len > n {
            return Err("Unexpected end of data while reading value".to_string());
        }

        let v = Value::try_from(&input[i..i + len])
            .map_err(|e| format!("Decoding error: {}", e.to_string()))?;
        i += len;
        println!("DECODE_OPERATION | result(middle): {:?}", result);
        // -- Step 3: decode the operation and update the set
        // if v == Value::try_from(&[]).unwrap() {}
        if f == 1 {
            println!("DECODE_OPERATION | inserting  {:?}", v.clone());
            result.insert(v);
        } else {
            result.remove(&v);
            println!("DECODE_OPERATION | (delete): {:?}", v);
        }
    }

    println!("DECODE_OPERATION | result: {:?}", result);

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

        let decoded = good_decode::<WORD_LENGTH, _, Value>(encoded)
            .expect("Decoding multiple values failed.");
        assert_eq!(decoded, values);
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

        let mut encoded = good_encode::<WORD_LENGTH, Value>(Op::Insert, values.clone())
            .expect("Encoding failed on overflow test.");

        let mut encoded2 = good_encode::<WORD_LENGTH, Value>(Op::Delete, values.clone())
            .expect("Encoding failed on  test.");

        // println!("Encoded: {:?}", encoded);
        // println!("Encoded2: {:?}", encoded2);

        encoded.append(&mut encoded2);
        // let combined_encoded: Vec<[u8; 129]> = [encoded.clone(), encoded2].concat();

        // combined_encoded.insert(Value::from();
        // println!("Combined: {:?}", combined_encoded);

        let decoded =
            good_decode::<WORD_LENGTH, _, Value>(encoded).expect("Decoding failed on  test.");

        assert_eq!(decoded, HashSet::new());
    }
}
