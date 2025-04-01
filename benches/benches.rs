use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
use cosmian_findex::{
    InMemory, bench_memory_contention, bench_memory_insert_multiple_bindings,
    bench_memory_search_multiple_bindings, bench_memory_search_multiple_keywords,
};
use criterion::{Criterion, criterion_group, criterion_main};

// Number of points in each graph.
const N_PTS: usize = 2;

const SQLITE_PATH: &str = "./target/benches.sqlite";
const REDIS_URL: &str = "redis://localhost:6379";

fn bench_search_multiple_bindings(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "rust-mem")]
    {
        bench_memory_search_multiple_bindings(
            "in-memory",
            N_PTS,
            async || InMemory::default(),
            c,
            &mut rng,
        );
    }

    #[cfg(feature = "redis-mem")]
    {
        use cosmian_findex::RedisMemory;

        bench_memory_search_multiple_bindings(
            "Redis",
            N_PTS,
            async || RedisMemory::connect(REDIS_URL).await.unwrap(),
            c,
            &mut rng,
        );
    }

    #[cfg(feature = "sqlite-mem")]
    {
        use cosmian_findex::SqliteMemory;
        bench_memory_search_multiple_bindings(
            "SQLite",
            N_PTS,
            async || SqliteMemory::connect(SQLITE_PATH).await.unwrap(),
            c,
            &mut rng,
        );
    }
}

fn bench_search_multiple_keywords(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "rust-mem")]
    {
        bench_memory_search_multiple_keywords(
            "in-memory",
            N_PTS,
            async || InMemory::default(),
            c,
            &mut rng,
        );
    }

    #[cfg(feature = "redis-mem")]
    {
        use cosmian_findex::RedisMemory;

        bench_memory_search_multiple_keywords(
            "Redis",
            N_PTS,
            async || RedisMemory::connect(REDIS_URL).await.unwrap(),
            c,
            &mut rng,
        );
    }

    #[cfg(feature = "sqlite-mem")]
    {
        use cosmian_findex::SqliteMemory;
        bench_memory_search_multiple_keywords(
            "SQLite",
            N_PTS,
            async || SqliteMemory::connect(SQLITE_PATH).await.unwrap(),
            c,
            &mut rng,
        );
    }
}

fn bench_insert_multiple_bindings(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    #[cfg(feature = "rust-mem")]
    {
        let clear = async |m: &InMemory<_, _>| -> Result<(), String> {
            m.clear();
            Ok(())
        };

        bench_memory_insert_multiple_bindings(
            "in-memory",
            N_PTS,
            async || InMemory::default(),
            c,
            clear,
            &mut rng,
        );
    }

    #[cfg(feature = "redis-mem")]
    {
        use cosmian_findex::RedisMemory;

        bench_memory_insert_multiple_bindings(
            "Redis",
            N_PTS,
            async || RedisMemory::connect(REDIS_URL).await.unwrap(),
            c,
            RedisMemory::clear,
            &mut rng,
        );
    }

    #[cfg(feature = "sqlite-mem")]
    {
        use cosmian_findex::SqliteMemory;

        bench_memory_insert_multiple_bindings(
            "SQLite",
            N_PTS,
            async || SqliteMemory::connect(SQLITE_PATH).await.unwrap(),
            c,
            SqliteMemory::clear,
            &mut rng,
        );
    }
}

fn bench_contention(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    {
        let clear = async |m: &InMemory<_, _>| -> Result<(), String> {
            m.clear();
            Ok(())
        };

        bench_memory_contention(
            "in-memory",
            N_PTS,
            async || InMemory::default(),
            c,
            clear,
            &mut rng,
        );
    }

    #[cfg(feature = "redis-mem")]
    {
        use cosmian_findex::RedisMemory;

        bench_memory_contention(
            "Redis",
            N_PTS,
            async || {
                RedisMemory::connect("redis://localhost:6379")
                    .await
                    .unwrap()
            },
            c,
            RedisMemory::clear,
            &mut rng,
        );
    }

    #[cfg(feature = "sqlite-mem")]
    {
        use cosmian_findex::SqliteMemory;

        bench_memory_contention(
            "SQLite",
            N_PTS,
            async || SqliteMemory::connect("benches.sqlite").await.unwrap(),
            c,
            SqliteMemory::clear,
            &mut rng,
        );
    }
}

criterion_group!(
    name    = benches;
    config  = Criterion::default().sample_size(5000);
    targets =
    bench_search_multiple_bindings,
    bench_search_multiple_keywords,
    bench_insert_multiple_bindings,
    bench_contention,
);

criterion_main!(benches);
