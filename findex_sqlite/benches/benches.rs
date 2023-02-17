use std::collections::HashSet;

use cosmian_findex::Keyword;
use cosmian_findex_sqlite::{search, upsert, utils::delete_db};
use criterion::{async_executor::FuturesExecutor, criterion_group, criterion_main, Criterion};
use futures::executor::block_on;

fn bench_upsert_search(c: &mut Criterion) {
    let nb_users = 100;
    let db_path = std::env::temp_dir().join("sqlite_bench.db");

    let mut group = c.benchmark_group("Findex");
    group.sample_size(10);
    group.bench_function(format!("Inserting {nb_users} users"), |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            //
            // Prepare database and create Findex structs
            //
            upsert(&db_path, "../datasets/data.json")
                .await
                .expect("upsert failed");
            delete_db(&db_path).unwrap();
        });
    });
    block_on(upsert(&db_path, "../datasets/data.json")).expect("upsert failed");
    group.bench_function("Searching 1 word (30 results)", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            let bulk_words = HashSet::from_iter([Keyword::from("France")]);
            search(&db_path, bulk_words, false)
                .await
                .expect("search failed");
        });
    });
    group.bench_function(format!("Searching 3 words ({nb_users} results)"), |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            let bulk_words = HashSet::from_iter([
                Keyword::from("France"),
                Keyword::from("Spain"),
                Keyword::from("Germany"),
            ]);
            search(&db_path, bulk_words, false)
                .await
                .expect("search failed");
        });
    });
    group.finish();
    delete_db(&db_path).unwrap();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(5000);
    targets =
        bench_upsert_search,
);

criterion_main!(benches);
