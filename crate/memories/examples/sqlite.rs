//! This example show-cases the use of Findex to securely store a hash-map with sqlite.
#[path = "shared_utils.rs"]
mod shared_utils;

use cosmian_crypto_core::{CsRng, Secret, reexport::rand_core::SeedableRng};
use cosmian_findex_memories::{
    SqliteMemory,
    reexport::cosmian_findex::{Findex, IndexADT, MemoryEncryptionLayer},
};
use futures::executor::block_on;
use shared_utils::{WORD_LENGTH, decoder, encoder, gen_index};
use std::collections::HashMap;

const DB_PATH: &str = "./target/debug/sqlite-test.db";

#[tokio::main]
async fn main() {
    // For cryptographic applications, it is important to use a secure RNG. In
    // Rust, those RNG implement the `CryptoRng` trait.
    let mut rng = CsRng::from_entropy();

    // Generate fresh Findex key. In practice only one user is in charge of
    // generating the key (the administrator?): all users *must* share the same
    // key in order to make the index inter-operable.
    let key = Secret::random(&mut rng);

    // Generating the random index.
    let index = gen_index(&mut rng);

    let memory = SqliteMemory::<_, [u8; WORD_LENGTH]>::connect(DB_PATH)
        .await
        .unwrap();

    let encrypted_memory = MemoryEncryptionLayer::new(&key, memory);

    // Instantiating Findex requires passing the key, the memory used and the
    // encoder and decoder. Quite simple, after all :)
    let findex = Findex::<
        WORD_LENGTH, // size of a word
        u64,         // type of a value
        String,      // type of an encoding error
        _,           // type of the memory
    >::new(encrypted_memory, encoder, decoder);

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

    println!("All good !");
}
