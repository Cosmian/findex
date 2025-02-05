//! This example show-cases the use of Findex to securely store a hash-map.

use cosmian_findex::{Findex, InMemory, IndexADT, MemoryEncryptionLayer, Op, Secret};
use futures::executor::block_on;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, SeedableRng};
use std::collections::{HashMap, HashSet};

/// This function generates a random set of (key, values) couples. Since Findex
/// API is those of an Index which only returns the *set* of values associated
/// to a given key, all random values generated here are stored in a `HashSet`.
///
/// In Findex's jargon, we say that these sets of values are *bound* to their
/// associated *keyword* of type `[u8; 8]` in this example. Since Findex only
/// requires from the values to be hashable, we could have taken any type that
/// implements `Hash` instead of the `u64`.
fn gen_index(rng: &mut impl CryptoRng) -> HashMap<[u8; 8], HashSet<u64>> {
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
const WORD_LENGTH: usize = 1 + 8 * 128;

fn encoder(op: Op, values: HashSet<u64>) -> Result<Vec<[u8; WORD_LENGTH]>, String> {
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

fn decoder(words: Vec<[u8; WORD_LENGTH]>) -> Result<HashSet<u64>, String> {
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

fn main() {
    // For cryptographic applications, it is important to use a secure RNG. In
    // Rust, those RNG implement the `CryptoRng` trait.
    let mut rng = ChaChaRng::from_os_rng();

    // Generate fresh Findex key. In practice only one user is in charge of
    // generating the key (the administrator?): all users *must* share the same
    // key in order to make the index inter-operable.
    let key = Secret::random(&mut rng);

    // Generating the random index.
    let index = gen_index(&mut rng);

    // For this example, we use the `InMemory` implementation of the `MemoryADT`
    // trait. It corresponds to an in-memory key-value store implemented on top
    // of a hash-table. For real application a DB such as Redis would be
    // preferred.
    let memory = MemoryEncryptionLayer::new(&key, InMemory::default());

    // Instantiating Findex requires passing the key, the memory used and the
    // encoder and decoder. Quite simple, after all :)
    let findex = Findex::<
        WORD_LENGTH, // size of a word
        u64,         // type of a value
        String,      // type of an encoding error
        _,           // type of the memory
    >::new(memory, encoder, decoder);

    // Here we insert all bindings one by one, blocking on each call. A better
    // way would be to performed all such calls in parallel using tasks.
    index
        .clone()
        .into_iter()
        .for_each(|(kw, vs)| block_on(findex.insert(kw, vs)).expect("insert failed"));

    // In order to verify insertion was correctly performed, we search for all
    // the indexed keywords...
    let res = index
        .keys()
        .cloned()
        .map(|kw| (kw, block_on(findex.search(&kw)).expect("search failed")))
        .collect::<HashMap<_, _>>();

    // ... and verify we get the whole index back!
    assert_eq!(res, index);

    println!("all good");
}
