use std::time::Duration;

use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
use cosmian_findex::{
    MemoryADT, bench_memory_contention, bench_memory_insert_multiple_bindings,
    bench_memory_one_to_many, bench_memory_search_multiple_bindings,
    bench_memory_search_multiple_keywords,
};
use criterion::{Criterion, criterion_group, criterion_main};
use rand::Rng;

#[cfg(feature = "rust-mem")]
use cosmian_findex::InMemory;

#[cfg(feature = "sqlite-mem")]
use cosmian_findex::SqliteMemory;

#[cfg(feature = "redis-mem")]
use cosmian_findex::{RedisMemory, RedisMemoryError};
use rand_distr::StandardNormal;

// Number of points in each graph.
const N_PTS: usize = 2;

#[cfg(feature = "sqlite-mem")]
const SQLITE_PATH: &str = "./target/benches.sqlite";

#[cfg(feature = "redis-mem")]
const REDIS_URL: &str = "redis://redis:6379";

// Use this URL for use with a local instance.
// const REDIS_URL: &str = "redis://localhost:6379";

#[cfg(feature = "postgres-mem")]
const POSTGRES_URL: &str = "postgres://cosmian:cosmian@localhost/cosmian";

#[cfg(feature = "postgres-mem")]
use deadpool_postgres::{Config, Pool};
#[cfg(feature = "postgres-mem")]
use tokio_postgres::NoTls;

#[cfg(feature = "postgres-mem")]
use cosmian_findex::{PostgresMemory, PostgresMemoryError};

#[cfg(feature = "postgres-mem")]
async fn create_testing_pool(db_url: &str) -> Result<Pool, PostgresMemoryError> {
    let mut pg_config = Config::new();
    pg_config.url = Some(db_url.to_string());
    let pool = pg_config.builder(NoTls)?.build()?;
    Ok(pool)
}

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

    #[cfg(feature = "postgres-mem")]
    bench_memory_search_multiple_bindings(
        "Postgres",
        N_PTS,
        async || {
            let table_name = "bench_memory_search_multiple_bindings";
            let m = PostgresMemory::connect_with_pool(
                create_testing_pool(POSTGRES_URL).await.unwrap(),
                table_name.to_owned(),
            )
            .await
            .unwrap();
            m.initialize_table(POSTGRES_URL.to_string(), table_name.to_string(), NoTls)
                .await
                .unwrap();
            m
        },
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

    #[cfg(feature = "postgres-mem")]
    bench_memory_search_multiple_keywords(
        "Postgres",
        N_PTS,
        async || {
            let table_name = "bench_memory_search_multiple_bindings";
            let m = PostgresMemory::connect_with_pool(
                create_testing_pool(POSTGRES_URL).await.unwrap(),
                table_name.to_owned(),
            )
            .await
            .unwrap();
            m.initialize_table(POSTGRES_URL.to_string(), table_name.to_string(), NoTls)
                .await
                .unwrap();
            m
        },
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

    #[cfg(feature = "postgres-mem")]
    bench_memory_insert_multiple_bindings(
        "Postgres",
        N_PTS,
        async || {
            let table_name = "bench_memory_insert_multiple_bindings";
            let m = PostgresMemory::connect_with_pool(
                create_testing_pool(POSTGRES_URL).await.unwrap(),
                table_name.to_owned(),
            )
            .await
            .unwrap();
            m.initialize_table(POSTGRES_URL.to_string(), table_name.to_string(), NoTls)
                .await
                .unwrap();
            m
        },
        c,
        async |m: &PostgresMemory<_, _>| -> Result<(), PostgresMemoryError> {
            m.clear("bench_memory_insert_multiple_bindings".to_owned())
                .await
        },
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

    #[cfg(feature = "postgres-mem")]
    bench_memory_contention(
        "Postgres",
        N_PTS,
        async || {
            let table_name = "bench_memory_contention";
            let m = PostgresMemory::connect_with_pool(
                create_testing_pool(POSTGRES_URL).await.unwrap(),
                table_name.to_owned(),
            )
            .await
            .unwrap();
            m.initialize_table(POSTGRES_URL.to_string(), table_name.to_string(), NoTls)
                .await
                .unwrap();
            m
        },
        c,
        async |m: &PostgresMemory<_, _>| -> Result<(), PostgresMemoryError> {
            m.clear("bench_memory_contention".to_owned()).await
        },
        &mut rng,
    );
}

#[derive(Clone, Debug)]
struct DelayedMemory<Memory> {
    m: Memory,
    mean: usize,
    variance: usize,
}

impl<Memory> DelayedMemory<Memory> {
    /// Wrap the given memory into a new delayed memory with an average network
    /// delay of s milliseconds.
    fn new(m: Memory, mean: usize, variance: usize) -> Self {
        Self { m, mean, variance }
    }

    fn delay(&self) -> Duration {
        let d =
            self.mean as f32 + self.variance as f32 * rand::rng().sample::<f32, _>(StandardNormal);
        // Use `max(d,1)` to prevent negative numbers and tiny delays.
        Duration::from_secs_f32(d.max(self.mean as f32 / 1_000.) / 1_000.)
    }
}

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
        tokio::time::sleep(self.delay()).await;
        self.m.batch_read(addresses).await
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        tokio::time::sleep(self.delay()).await;
        self.m.guarded_write(guard, bindings).await
    }
}

#[cfg(feature = "redis-mem")]
impl<Address, Word> DelayedMemory<RedisMemory<Address, Word>>
where
    Address: Send + Sync,
    Word: Send + Sync,
{
    async fn clear(&self) -> Result<(), RedisMemoryError> {
        self.m.clear().await
    }
}

fn bench_one_to_many(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "redis-mem")]
    bench_memory_one_to_many(
        "Redis",
        N_PTS,
        async || DelayedMemory::new(RedisMemory::connect(REDIS_URL).await.unwrap(), 1, 1),
        c,
        DelayedMemory::clear,
        &mut rng,
    );

    #[cfg(feature = "redis-mem")]
    bench_memory_one_to_many(
        "Redis",
        N_PTS,
        async || DelayedMemory::new(RedisMemory::connect(REDIS_URL).await.unwrap(), 10, 1),
        c,
        DelayedMemory::clear,
        &mut rng,
    );

    #[cfg(feature = "redis-mem")]
    bench_memory_one_to_many(
        "Redis",
        N_PTS,
        async || DelayedMemory::new(RedisMemory::connect(REDIS_URL).await.unwrap(), 10, 5),
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
