use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
use cosmian_findex::{
    InMemory, bench_memory_contention, bench_memory_insert_multiple_bindings,
    bench_memory_search_multiple_bindings, bench_memory_search_multiple_keywords,
};
use criterion::{Criterion, criterion_group, criterion_main};

const N: usize = 2;

fn bench_search_multiple_bindings(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    {
        bench_memory_search_multiple_bindings(
            "in-memory",
            N,
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
            N,
            async || {
                RedisMemory::connect("redis://localhost:6379")
                    .await
                    .unwrap()
            },
            c,
            &mut rng,
        );
    }

    #[cfg(feature = "sqlite-mem")]
    {
        use cosmian_findex::SqliteMemory;
        bench_memory_search_multiple_bindings(
            "SQLite",
            N,
            async || SqliteMemory::connect("benches.sqlite").await.unwrap(),
            c,
            &mut rng,
        );
    }
}

fn bench_search_multiple_keywords(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    {
        bench_memory_search_multiple_keywords(
            "in-memory",
            N,
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
            N,
            async || {
                RedisMemory::connect("redis://localhost:6379")
                    .await
                    .unwrap()
            },
            c,
            &mut rng,
        );
    }

    #[cfg(feature = "sqlite-mem")]
    {
        use cosmian_findex::SqliteMemory;
        bench_memory_search_multiple_keywords(
            "SQLite",
            N,
            async || SqliteMemory::connect("benches.sqlite").await.unwrap(),
            c,
            &mut rng,
        );
    }
}

fn bench_insert_multiple_bindings(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    {
        let clear = async |m: &InMemory<_, _>| -> Result<(), String> {
            m.clear();
            Ok(())
        };

        bench_memory_insert_multiple_bindings(
            "in-memory",
            N,
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
            N,
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

        bench_memory_insert_multiple_bindings(
            "SQLite",
            N,
            async || SqliteMemory::connect("benches.sqlite").await.unwrap(),
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
            N,
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
            N,
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
            N,
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
