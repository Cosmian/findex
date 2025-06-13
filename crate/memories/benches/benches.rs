// It is too much trouble to deactivate everything if none of the features are
// activated.
#![allow(unused_imports, unused_variables, unused_mut, dead_code)]

use cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_findex::{
    bench_memory_contention, bench_memory_insert_multiple_bindings, bench_memory_one_to_many,
    bench_memory_search_multiple_bindings, bench_memory_search_multiple_keywords,
};
use criterion::{Criterion, criterion_group, criterion_main};

#[cfg(feature = "sqlite-mem")]
use cosmian_findex_memories::SqliteMemory;
#[cfg(feature = "sqlite-mem")]
const SQLITE_PATH: &str = "benches.sqlite.db";

#[cfg(feature = "redis-mem")]
use cosmian_findex_memories::RedisMemory;

#[cfg(feature = "redis-mem")]
fn get_redis_url() -> String {
    std::env::var("REDIS_HOST").map_or_else(
        |_| "redis://localhost:6379".to_owned(),
        |var_env| format!("redis://{var_env}:6379"),
    )
}

#[cfg(feature = "postgres-mem")]
use cosmian_findex_memories::{PostgresMemory, PostgresMemoryError};

// To run the postgresql benchmarks locally, add the following service to your pg_service.conf file
// (usually under ~/.pg_service.conf):
//
// [cosmian_service]
// host=localhost
// dbname=cosmian
// user=cosmian
// password=cosmian
#[cfg(feature = "postgres-mem")]
fn get_postgresql_url() -> String {
    std::env::var("POSTGRES_HOST").map_or_else(
        |_| "postgres://cosmian:cosmian@localhost/cosmian".to_string(),
        |var_env| format!("postgres://cosmian:cosmian@{var_env}/cosmian"),
    )
}

use cosmian_findex::{ADDRESS_LENGTH, Address, WORD_LENGTH};
// Utility function used to initialize the PostgresMemory table
#[cfg(feature = "postgres-mem")]
async fn connect_and_init_table(
    db_url: String,
    table_name: String,
) -> Result<PostgresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>, PostgresMemoryError> {
    use deadpool_postgres::Config;
    use tokio_postgres::NoTls;

    let mut pg_config = Config::new();
    pg_config.url = Some(db_url.to_string());
    let test_pool = pg_config.builder(NoTls)?.build()?;

    let m = PostgresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::new_with_pool(
        test_pool,
        table_name.to_string(),
    )
    .await;

    m.initialize().await?;

    Ok(m)
}
// Number of points in each graph.
const N_PTS: usize = 9;

fn bench_search_multiple_bindings(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "redis-mem")]
    bench_memory_search_multiple_bindings(
        "Redis",
        N_PTS,
        async || RedisMemory::new_with_url(&get_redis_url()).await.unwrap(),
        c,
        &mut rng,
    );

    #[cfg(feature = "sqlite-mem")]
    bench_memory_search_multiple_bindings(
        "SQLite",
        N_PTS,
        async || {
            let m = SqliteMemory::new_with_path(
                SQLITE_PATH,
                "bench_memory_search_multiple_bindings".to_string(),
            )
            .await
            .unwrap();
            m.initialize().await.unwrap();
            m
        },
        c,
        &mut rng,
    );

    #[cfg(feature = "postgres-mem")]
    bench_memory_search_multiple_bindings(
        "Postgres",
        N_PTS,
        async || {
            let m = connect_and_init_table(
                get_postgresql_url(),
                "bench_memory_search_multiple_bindings".to_string(),
            )
            .await
            .unwrap();
            m.initialize().await.unwrap();
            m
        },
        c,
        &mut rng,
    );
}

fn bench_search_multiple_keywords(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "redis-mem")]
    bench_memory_search_multiple_keywords(
        "Redis",
        N_PTS,
        async || RedisMemory::new_with_url(&get_redis_url()).await.unwrap(),
        c,
        &mut rng,
    );

    #[cfg(feature = "sqlite-mem")]
    bench_memory_search_multiple_keywords(
        "SQLite",
        N_PTS,
        async || {
            let m = SqliteMemory::new_with_path(
                SQLITE_PATH,
                "bench_memory_search_multiple_keywords".to_string(),
            )
            .await
            .unwrap();
            m.initialize().await.unwrap();
            m
        },
        c,
        &mut rng,
    );

    #[cfg(feature = "postgres-mem")]
    bench_memory_search_multiple_keywords(
        "Postgres",
        N_PTS,
        async || {
            connect_and_init_table(
                get_postgresql_url(),
                "bench_memory_search_multiple_keywords".to_string(),
            )
            .await
            .unwrap()
        },
        c,
        &mut rng,
    );
}

fn bench_insert_multiple_bindings(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "redis-mem")]
    bench_memory_insert_multiple_bindings(
        "Redis",
        N_PTS,
        async || RedisMemory::new_with_url(&get_redis_url()).await.unwrap(),
        c,
        RedisMemory::clear,
        &mut rng,
    );

    #[cfg(feature = "sqlite-mem")]
    bench_memory_insert_multiple_bindings(
        "SQLite",
        N_PTS,
        async || {
            let m = SqliteMemory::new_with_path(
                SQLITE_PATH,
                "bench_memory_insert_multiple_bindings".to_string(),
            )
            .await
            .unwrap();
            m.initialize().await.unwrap();
            m
        },
        c,
        SqliteMemory::clear,
        &mut rng,
    );

    #[cfg(feature = "postgres-mem")]
    bench_memory_insert_multiple_bindings(
        "Postgres",
        N_PTS,
        async || {
            connect_and_init_table(
                get_postgresql_url(),
                "bench_memory_insert_multiple_bindings".to_string(),
            )
            .await
            .unwrap()
        },
        c,
        async |m: &PostgresMemory<_, _>| -> Result<(), String> {
            m.clear().await.map_err(|e| e.to_string())
        },
        &mut rng,
    );
}

fn bench_contention(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "redis-mem")]
    bench_memory_contention(
        "Redis",
        N_PTS,
        async || RedisMemory::new_with_url(&get_redis_url()).await.unwrap(),
        c,
        RedisMemory::clear,
        &mut rng,
    );

    #[cfg(feature = "sqlite-mem")]
    bench_memory_contention(
        "SQLite",
        N_PTS,
        async || {
            let m = SqliteMemory::new_with_path(SQLITE_PATH, "bench_memory_contention".to_string())
                .await
                .unwrap();
            m.initialize().await.unwrap();
            m
        },
        c,
        SqliteMemory::clear,
        &mut rng,
    );

    #[cfg(feature = "postgres-mem")]
    bench_memory_contention(
        "Postgres",
        N_PTS,
        async || {
            connect_and_init_table(get_postgresql_url(), "bench_memory_contention".to_string())
                .await
                .unwrap()
        },
        c,
        async |m: &PostgresMemory<_, _>| -> Result<(), String> {
            m.clear().await.map_err(|e| e.to_string())
        },
        &mut rng,
    );
}

#[cfg(any(feature = "redis-mem", feature = "postgres-mem"))]
mod delayed_memory {
    use cosmian_findex::{Address, MemoryADT};
    use cosmian_findex_memories::{
        PostgresMemory, PostgresMemoryError, RedisMemory, RedisMemoryError,
    };
    use rand::Rng;
    use rand_distr::StandardNormal;
    use std::time::Duration;

    #[derive(Clone, Debug)]
    pub struct DelayedMemory<Memory> {
        m: Memory,
        mean: usize,
        variance: usize,
    }

    #[cfg(any(feature = "redis-mem", feature = "postgres-mem"))]
    impl<Memory> DelayedMemory<Memory> {
        /// Wrap the given memory into a new delayed memory with an average network
        /// delay of s milliseconds.
        pub fn new(m: Memory, mean: usize, variance: usize) -> Self {
            Self { m, mean, variance }
        }

        pub fn delay(&self) -> Duration {
            let d = self.mean as f32
                + self.variance as f32 * rand::rng().sample::<f32, _>(StandardNormal);
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
        pub async fn clear(&self) -> Result<(), RedisMemoryError> {
            self.m.clear().await
        }
    }

    #[cfg(feature = "postgres-mem")]
    impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize>
        DelayedMemory<PostgresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>>
    {
        pub async fn clear(&self) -> Result<(), PostgresMemoryError> {
            self.m.clear().await
        }
    }
}

fn bench_one_to_many(c: &mut Criterion) {
    #[cfg(feature = "redis-mem")]
    let mut rng = CsRng::from_entropy();

    #[cfg(any(feature = "redis-mem", feature = "postgres-mem"))]
    use delayed_memory::*;

    let delay_params = vec![(1, 1), (10, 1), (10, 5)]; // tuples of (mean, variance)

    #[cfg(feature = "redis-mem")]
    for (mean, variance) in &delay_params {
        bench_memory_one_to_many(
            "Redis",
            N_PTS,
            async || {
                DelayedMemory::new(
                    RedisMemory::new_with_url(&get_redis_url()).await.unwrap(),
                    *mean,
                    *variance,
                )
            },
            c,
            DelayedMemory::<RedisMemory<_, _>>::clear,
            &mut rng,
        );
    }

    #[cfg(feature = "postgres-mem")]
    for (mean, variance) in &delay_params {
        bench_memory_one_to_many(
            "Postgres",
            N_PTS,
            async || {
                let m = connect_and_init_table(
                    get_postgresql_url(),
                    format!("bench_memory_one_to_many_m_{}_var_{}", *mean, *variance),
                )
                .await
                .unwrap();
                DelayedMemory::new(m, *mean, *variance)
            },
            c,
            DelayedMemory::<PostgresMemory<_, _>>::clear,
            &mut rng,
        );
    }
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
