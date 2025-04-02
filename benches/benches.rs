use std::time::Duration;

use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
use cosmian_findex::{
    MemoryADT, RedisMemoryError, bench_memory_contention, bench_memory_insert_multiple_bindings,
    bench_memory_one_to_many, bench_memory_search_multiple_bindings,
    bench_memory_search_multiple_keywords,
};
use criterion::{Criterion, criterion_group, criterion_main};

#[cfg(feature = "rust-mem")]
use cosmian_findex::InMemory;

#[cfg(feature = "sqlite-mem")]
use cosmian_findex::SqliteMemory;

#[cfg(feature = "redis-mem")]
use cosmian_findex::RedisMemory;

// Number of points in each graph.
const N_PTS: usize = 2;

#[cfg(feature = "sqlite-mem")]
const SQLITE_PATH: &str = "./target/benches.sqlite";

#[cfg(feature = "redis-mem")]
const REDIS_URL: &str = "redis://localhost:6379";

fn bench_search_multiple_bindings(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "rust-mem")]
    bench_memory_search_multiple_bindings(
        "in-memory",
        N_PTS,
        async || InMemory::default(),
        c,
        &mut rng,
    );

    #[cfg(feature = "redis-mem")]
    bench_memory_search_multiple_bindings(
        "Redis",
        N_PTS,
        async || RedisMemory::connect(REDIS_URL).await.unwrap(),
        c,
        &mut rng,
    );

    #[cfg(feature = "sqlite-mem")]
    bench_memory_search_multiple_bindings(
        "SQLite",
        N_PTS,
        async || SqliteMemory::connect(SQLITE_PATH).await.unwrap(),
        c,
        &mut rng,
    );
}

fn bench_search_multiple_keywords(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "rust-mem")]
    bench_memory_search_multiple_keywords(
        "in-memory",
        N_PTS,
        async || InMemory::default(),
        c,
        &mut rng,
    );

    #[cfg(feature = "redis-mem")]
    bench_memory_search_multiple_keywords(
        "Redis",
        N_PTS,
        async || RedisMemory::connect(REDIS_URL).await.unwrap(),
        c,
        &mut rng,
    );

    #[cfg(feature = "sqlite-mem")]
    bench_memory_search_multiple_keywords(
        "SQLite",
        N_PTS,
        async || SqliteMemory::connect(SQLITE_PATH).await.unwrap(),
        c,
        &mut rng,
    );
}

fn bench_insert_multiple_bindings(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "rust-mem")]
    bench_memory_insert_multiple_bindings(
        "in-memory",
        N_PTS,
        async || InMemory::default(),
        c,
        async |m: &InMemory<_, _>| -> Result<(), String> {
            m.clear();
            Ok(())
        },
        &mut rng,
    );

    #[cfg(feature = "redis-mem")]
    bench_memory_insert_multiple_bindings(
        "Redis",
        N_PTS,
        async || RedisMemory::connect(REDIS_URL).await.unwrap(),
        c,
        RedisMemory::clear,
        &mut rng,
    );

    #[cfg(feature = "sqlite-mem")]
    bench_memory_insert_multiple_bindings(
        "SQLite",
        N_PTS,
        async || SqliteMemory::connect(SQLITE_PATH).await.unwrap(),
        c,
        SqliteMemory::clear,
        &mut rng,
    );
}

fn bench_contention(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "rust-mem")]
    bench_memory_contention(
        "in-memory",
        N_PTS,
        async || InMemory::default(),
        c,
        async |m: &InMemory<_, _>| -> Result<(), String> {
            m.clear();
            Ok(())
        },
        &mut rng,
    );

    #[cfg(feature = "redis-mem")]
    bench_memory_contention(
        "Redis",
        N_PTS,
        async || RedisMemory::connect(REDIS_URL).await.unwrap(),
        c,
        RedisMemory::clear,
        &mut rng,
    );

    #[cfg(feature = "sqlite-mem")]
    bench_memory_contention(
        "SQLite",
        N_PTS,
        async || SqliteMemory::connect(SQLITE_PATH).await.unwrap(),
        c,
        SqliteMemory::clear,
        &mut rng,
    );
}

#[derive(Clone, Debug)]
struct DelayedMemory<Memory>(Memory);

impl<Memory> MemoryADT for DelayedMemory<Memory>
where
    Memory: Send + Sync + MemoryADT,
    Memory::Address: Send + Sync,
    Memory::Word: Send + Sync,
{
    type Address = Memory::Address;

    type Word = Memory::Word;

    type Error = Memory::Error;

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        tokio::time::sleep(Duration::from_millis(1)).await;
        self.0.batch_read(addresses).await
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        tokio::time::sleep(Duration::from_millis(1)).await;
        self.0.guarded_write(guard, bindings).await
    }
}

#[cfg(feature = "redis-mem")]
impl<Address, Word> DelayedMemory<RedisMemory<Address, Word>>
where
    Address: Send + Sync,
    Word: Send + Sync,
{
    async fn clear(&self) -> Result<(), RedisMemoryError> {
        self.0.clear().await
    }
}

fn bench_one_to_many(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "redis-mem")]
    bench_memory_one_to_many(
        "Redis",
        N_PTS,
        async || DelayedMemory(RedisMemory::connect(REDIS_URL).await.unwrap()),
        c,
        DelayedMemory::clear,
        &mut rng,
    );
}

criterion_group!(
    name    = benches;
    config  = Criterion::default();
    targets =
    bench_one_to_many,
    bench_search_multiple_bindings,
    bench_search_multiple_keywords,
    bench_insert_multiple_bindings,
    bench_contention,
);

criterion_main!(benches);
