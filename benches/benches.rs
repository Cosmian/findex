#[cfg(feature = "sqlite")]
use cosmian_findex::interfaces::sqlite::{delete_db, search, upsert};
#[cfg(feature = "sqlite")]
use criterion::{async_executor::FuturesExecutor, criterion_group, criterion_main, Criterion};

#[cfg(feature = "sqlite")]
fn bench_upsert_search(c: &mut Criterion) {
    //
    // Generate new dataset
    //

    use std::collections::HashSet;

    use cosmian_findex::core::Keyword;

    let nb_users = 100;

    delete_db("sqlite_bench.db").unwrap();

    let mut group = c.benchmark_group("Findex");
    group.sample_size(10);
    group.bench_function(format!("Inserting {nb_users} users"), |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            delete_db("sqlite_bench.db").unwrap();
            //
            // Prepare database and create Findex structs
            //
            upsert("sqlite_bench.db", "./datasets/data.json")
                .await
                .expect("upsert failed");
        });
    });
    group.bench_function("Searching 1 word (30 results)", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            let bulk_words = HashSet::from_iter([Keyword::from("France")]);
            search("sqlite_bench.db", bulk_words, false)
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
            search("sqlite_bench.db", bulk_words, false)
                .await
                .expect("search failed");
        });
    });
    group.finish();
    delete_db("sqlite_bench.db").unwrap();
}

#[cfg(feature = "sqlite")]
criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(5000);
    targets =
        bench_upsert_search,
);

#[cfg(feature = "sqlite")]
criterion_main!(benches);

#[cfg(all(not(feature = "sqlite")))]
fn main() {}
