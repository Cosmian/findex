// It is too much trouble to deactivate everything if none of the features are
// activated.
#![allow(unused_imports, unused_variables, unused_mut, dead_code)]

use cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_findex::{
    WORD_LENGTH, bench_memory_contention, bench_memory_insert_multiple_bindings,
    bench_memory_one_to_many, bench_memory_search_multiple_bindings,
    bench_memory_search_multiple_keywords, reexport::tokio::TokioRuntime,
};
use cosmian_sse_memories::InMemory;
use criterion::{Criterion, criterion_group, criterion_main};
use tokio::runtime::{Builder, Runtime};

fn get_database_args() -> (bool, bool, bool) {
    let args: Vec<String> = std::env::args().collect();

    let redis_enabled = check_arg(&args, "redis");
    let postgres_enabled = check_arg(&args, "postgres");
    let sqlite_enabled = check_arg(&args, "sqlite");

    (redis_enabled, postgres_enabled, sqlite_enabled)
}

fn check_arg(args: &[String], arg_name: &str) -> bool {
    if let Ok(env_val) = std::env::var(format!("{}_HOST", arg_name.to_uppercase())) {
        return true;
    }

    let arg = format!("--{}", arg_name);

    if let Some(pos) = args.iter().position(|a| a == &arg) {
        if let Some(value) = args.get(pos + 1) {
            if !value.starts_with("--") {
                return !matches!(value.as_str(), "0" | "false" | "False" | "FALSE");
            }
        }
    }
    // Default to enabled if arg is not explicitly disabled
    true
}

use cosmian_sse_memories::SqliteMemory;
const SQLITE_PATH: &str = "benches.sqlite.db";

// Redis memory back-end requires a tokio runtime, and all operations to
// happen in the same runtime, otherwise the connection returns a broken
// pipe error.
use cosmian_sse_memories::RedisMemory;

fn get_redis_url() -> String {
    std::env::var("REDIS_HOST").map_or_else(
        |_| "redis://localhost:6379".to_owned(),
        |var_env| format!("redis://{var_env}:6379"),
    )
}

use cosmian_sse_memories::{ADDRESS_LENGTH, Address, PostgresMemory, PostgresMemoryError};

fn get_postgresql_url() -> String {
    std::env::var("POSTGRES_HOST").map_or_else(
        |_| "postgres://cosmian:cosmian@localhost/cosmian".to_string(),
        |var_env| format!("postgres://cosmian:cosmian@{var_env}/cosmian"),
    )
}

// Utility function used to initialize the PostgresMemory table
async fn connect_and_init_table(
    db_url: String,
    table_name: String,
) -> Result<PostgresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>, PostgresMemoryError> {
    use cosmian_sse_memories::reexport::deadpool_postgres::Config;
    use cosmian_sse_memories::reexport::tokio_postgres::NoTls;

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
    let (redis_enabled, postgres_enabled, sqlite_enabled) = get_database_args();
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    let _guard = rt.enter();

    bench_memory_search_multiple_bindings::<_, TokioRuntime>(
        "in-memory",
        N_PTS,
        async || InMemory::default(),
        c,
        &mut rng,
    );

    if redis_enabled {
        bench_memory_search_multiple_bindings::<_, TokioRuntime>(
            "Redis",
            N_PTS,
            async || RedisMemory::new_with_url(&get_redis_url()).await.unwrap(),
            c,
            &mut rng,
        );
    }

    if sqlite_enabled {
        bench_memory_search_multiple_bindings::<_, TokioRuntime>(
            "SQLite",
            N_PTS,
            async || {
                let m = SqliteMemory::new_with_path(SQLITE_PATH, "bench_memory_smd".to_string())
                    .await
                    .unwrap();
                m.initialize().await.unwrap();
                m
            },
            c,
            &mut rng,
        );
    }

    if postgres_enabled {
        bench_memory_search_multiple_bindings::<_, TokioRuntime>(
            "Postgres",
            N_PTS,
            async || {
                let m =
                    connect_and_init_table(get_postgresql_url(), "bench_memory_smd".to_string())
                        .await
                        .unwrap();
                m.initialize().await.unwrap();
                m
            },
            c,
            &mut rng,
        );
    }
}
fn bench_search_multiple_keywords(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    let _guard = rt.enter();

    bench_memory_search_multiple_keywords::<_, TokioRuntime>(
        "in-memory",
        N_PTS,
        async || InMemory::default(),
        c,
        &mut rng,
    );

    #[cfg(feature = "redis-mem")]
    bench_memory_search_multiple_keywords::<_, TokioRuntime>(
        "Redis",
        N_PTS,
        async || RedisMemory::new_with_url(&get_redis_url()).await.unwrap(),
        c,
        &mut rng,
    );

    #[cfg(feature = "sqlite-mem")]
    bench_memory_search_multiple_keywords::<_, TokioRuntime>(
        "SQLite",
        N_PTS,
        async || {
            let m = SqliteMemory::new_with_path(SQLITE_PATH, "bench_memory_smk".to_string())
                .await
                .unwrap();
            m.initialize().await.unwrap();
            m
        },
        c,
        &mut rng,
    );

    #[cfg(feature = "postgres-mem")]
    bench_memory_search_multiple_keywords::<_, TokioRuntime>(
        "Postgres",
        N_PTS,
        async || {
            connect_and_init_table(get_postgresql_url(), "bench_memory_smk".to_string())
                .await
                .unwrap()
        },
        c,
        &mut rng,
    );
}
fn bench_insert_multiple_bindings(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    let _guard = rt.enter();

    bench_memory_insert_multiple_bindings::<_, _, TokioRuntime>(
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
    bench_memory_insert_multiple_bindings::<_, _, TokioRuntime>(
        "Redis",
        N_PTS,
        async || RedisMemory::new_with_url(&get_redis_url()).await.unwrap(),
        c,
        RedisMemory::clear,
        &mut rng,
    );

    #[cfg(feature = "sqlite-mem")]
    bench_memory_insert_multiple_bindings::<_, _, TokioRuntime>(
        "SQLite",
        N_PTS,
        async || {
            let m = SqliteMemory::new_with_path(SQLITE_PATH, "bench_memory_imd".to_string())
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
    bench_memory_insert_multiple_bindings::<_, _, TokioRuntime>(
        "Postgres",
        N_PTS,
        async || {
            connect_and_init_table(get_postgresql_url(), "bench_memory_imd".to_string())
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
    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    let _guard = rt.enter();

    bench_memory_contention::<_, _, TokioRuntime>(
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
    bench_memory_contention::<_, _, TokioRuntime>(
        "Redis",
        N_PTS,
        async || RedisMemory::new_with_url(&get_redis_url()).await.unwrap(),
        c,
        RedisMemory::clear,
        &mut rng,
    );

    #[cfg(feature = "sqlite-mem")]
    bench_memory_contention::<_, _, TokioRuntime>(
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
    bench_memory_contention::<_, _, TokioRuntime>(
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
    #[cfg(feature = "postgres-mem")]
    use cosmian_sse_memories::{
        Address, MemoryADT, PostgresMemory, PostgresMemoryError, RedisMemory, RedisMemoryError,
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

    impl<Memory: Send + Sync + MemoryADT> MemoryADT for DelayedMemory<Memory> {
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
        Address: Send,
        Word: Send,
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

#[cfg(any(feature = "redis-mem", feature = "postgres-mem"))]
fn bench_one_to_many(c: &mut Criterion) {
    use delayed_memory::DelayedMemory;

    let mut rng = CsRng::from_entropy();
    let delay_params = [(1, 1), (10, 1), (10, 5)]; // tuples of (mean, variance)

    let rt = Builder::new_multi_thread().enable_all().build().unwrap();
    let _guard = rt.enter();

    #[cfg(feature = "redis-mem")]
    for (mean, variance) in &delay_params {
        bench_memory_one_to_many::<_, _, TokioRuntime>(
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
        bench_memory_one_to_many::<_, _, TokioRuntime>(
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
