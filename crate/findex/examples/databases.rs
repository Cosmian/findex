//! This example show-cases the use of Findex to securely store a hash-map with
//! different back ends.
#[path = "shared_utils.rs"]
mod shared_utils;

use std::collections::HashMap;

use cosmian_crypto_core::{CsRng, Secret, reexport::rand_core::SeedableRng};
use cosmian_findex::{Findex, IndexADT, MemoryEncryptionLayer};
use cosmian_sse_memories::{
    ADDRESS_LENGTH, Address, PostgresMemory, PostgresMemoryError, RedisMemory, SqliteMemory,
    reexport::{
        deadpool_postgres::{Config, Pool},
        tokio_postgres::NoTls,
    },
};
use shared_utils::{WORD_LENGTH, decoder, encoder, gen_index};

const REDIS_URL: &str = "redis://localhost:6379";
const SQLITE_DB_PATH: &str = "./target/debug/sqlite-test.db";
const PGSQL_URL: &str = "postgres://cosmian:cosmian@localhost/cosmian";
const TABLE_NAME: &str = "findex_memory";

async fn create_pool(db_url: &str) -> Result<Pool, PostgresMemoryError> {
    let mut pg_config = Config::new();
    pg_config.url = Some(db_url.to_string());
    let pool = pg_config.builder(NoTls)?.build()?;
    Ok(pool)
}

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

    // This example uses our Redis-based implementation of `MemoryADT`.
    let redis_memory =
        RedisMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::new_with_url(REDIS_URL)
            .await
            .unwrap();

    // You can also use our Sqlite-based implementation of `MemoryADT`.
    let _sqlite_memory = SqliteMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::new_with_path(
        SQLITE_DB_PATH,
        TABLE_NAME.to_owned(),
    )
    .await
    .unwrap();

    // Or else, the Postgres-based implementation of `MemoryADT`. Refer to README.md
    // for details on how to setup the database to use this example.
    let pool = create_pool(PGSQL_URL).await.unwrap();
    let _postgres_memory =
        PostgresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::new_with_pool(
            pool.clone(),
            TABLE_NAME.to_string(),
        )
        .await;

    // Adding an encryption layer to the chosen memory
    let encrypted_memory = MemoryEncryptionLayer::new(&key, redis_memory);

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
    for (kw, vs) in index.clone().into_iter() {
        findex.insert(kw, vs).await.expect("insert failed");
    }
    // In order to verify insertion was correctly performed, we search for all
    // the indexed keywords...
    let mut res = HashMap::new();
    for kw in index.keys().cloned() {
        let search_results = findex.search(&kw).await.expect("search failed");
        res.insert(kw, search_results);
    }

    // ... and verify we get the whole index back!
    assert_eq!(res, index);

    println!("All good !");
}
