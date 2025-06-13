//! This example show-cases the use of Findex to securely store a hash-map with
//! PostgreSQL.
#[path = "shared_utils.rs"]
mod shared_utils;

use cosmian_crypto_core::{CsRng, Secret, reexport::rand_core::SeedableRng};
use cosmian_findex_memories::{
    PostgresMemory, PostgresMemoryError,
    reexport::{
        cosmian_findex::{ADDRESS_LENGTH, Address, Findex, IndexADT, MemoryEncryptionLayer},
        deadpool_postgres::{Config, Pool},
        tokio_postgres::NoTls,
    },
};
use futures::executor::block_on;
use shared_utils::{WORD_LENGTH, decoder, encoder, gen_index};
use std::collections::HashMap;

const DB_URL: &str = "postgres://cosmian:cosmian@localhost/cosmian";
const TABLE_NAME: &str = "findex_example";

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

    // Generating a random index.
    let index = gen_index(&mut rng);

    // Addd the following service to your pg_service.conf file (usually under
    // `~/.pg_service.conf`):
    //
    // [cosmian_service]
    // host=localhost
    // dbname=cosmian
    // user=cosmian
    // password=cosmian
    let pool = create_pool(DB_URL).await.unwrap();
    let m = PostgresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::new_with_pool(
        pool.clone(),
        TABLE_NAME.to_string(),
    )
    .await;

    // Notice we chose to not enable TLS: it's not needed for this example as we
    // are using the encryption layer in top of the memory interface - i.e. the
    // data is already encrypted before being sent to the database and TLS would
    // add unnecessary overhead.
    m.initialize().await.unwrap();

    let encrypted_memory = MemoryEncryptionLayer::new(&key, m);

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

    // Drop the table to avoid problems with subsequent runs.
    pool.get()
        .await
        .unwrap()
        .execute(&format!("DROP table {};", TABLE_NAME), &[])
        .await
        .unwrap();

    println!("All good !");
}
