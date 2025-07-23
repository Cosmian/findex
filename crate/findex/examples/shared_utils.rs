use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;
use cosmian_findex::Op;
use std::collections::{HashMap, HashSet};

/// This function generates a random set of (key, values) couples. Since Findex
/// API is those of an Index which only returns the *set* of values associated
/// to a given key, all random values generated here are stored in a `HashSet`.
///
/// In Findex's jargon, we say that these sets of values are *bound* to their
/// associated *keyword* of type `[u8; 8]` in this example. Since Findex only
/// requires from the values to be hashable, we could have taken any type that
/// implements `Hash` instead of the `u64`.
pub fn gen_index(rng: &mut impl CryptoRngCore) -> HashMap<[u8; 8], HashSet<u64>> {
    (0..6)
        .map(|i| {
            let kw = rng.next_u64().to_be_bytes();
            let vals = (0..10_i64.pow(i) as usize)
                .map(|_| rng.next_u64())
                .collect::<HashSet<_>>();
            (kw, vals)
        })
        .collect()
}

/// The encoder will use 1 bit to encode the operation (insert or delete), and 7
/// bits to encode the number of values (of type u64) in the word. This allows
/// for words of 2^7 = 128 values, which are serialized into an array of 8 bytes
/// each. The `WORD_LENGTH` is therefore 1 byte of metadata plus 128 * 8 bytes
/// of values.
pub const WORD_LENGTH: usize = 1 + 8 * 128;

pub fn encoder(op: Op, values: HashSet<u64>) -> Result<Vec<[u8; WORD_LENGTH]>, String> {
    let mut words = Vec::new(); // This could be initialized with the correct size.
    let mut values = values.into_iter().peekable();
    while values.peek().is_some() {
        let chunk = (0..128)
            .filter_map(|_| values.next())
            .map(|v| v.to_be_bytes())
            .collect::<Vec<_>>();

        let metadata =
            <u8>::try_from(chunk.len() - 1).unwrap() + if let Op::Insert = op { 128 } else { 0 };
        let mut word = [0; WORD_LENGTH];
        word[0] = metadata;
        chunk
            .into_iter()
            .enumerate()
            .for_each(|(i, v)| word[1 + i * 8..1 + (i + 1) * 8].copy_from_slice(v.as_slice()));
        words.push(word);
    }
    Ok(words)
}

pub fn decoder(words: Vec<[u8; WORD_LENGTH]>) -> Result<HashSet<u64>, String> {
    let mut values = HashSet::new();
    words.into_iter().for_each(|w| {
        let metadata = w[0];

        // Extract the highest bit to recover the operation.
        let op = if metadata < 128 {
            Op::Delete
        } else {
            Op::Insert
        };

        // Remove the highest bit to recover the number of values.
        let n = metadata & 127;

        for i in 0..=n as usize {
            let v = u64::from_be_bytes(w[1 + i * 8..1 + (i + 1) * 8].try_into().unwrap());
            if let Op::Insert = op {
                values.insert(v);
            } else {
                values.remove(&v);
            }
        }
    });

    Ok(values)
}

#[allow(dead_code)]
fn main() {
    panic!("This is a utility module and should not be run directly.");
}
