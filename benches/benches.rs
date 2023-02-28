use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::CsRng;
use cosmian_findex::{
    in_memory_example::FindexInMemory, parameters::SECURE_FETCH_CHAINS_BATCH_SIZE, FindexSearch,
    FindexUpsert, IndexedValue, KeyingMaterial, Keyword, Label, Location,
};
// use cosmian_findex_in_memory::interfaces::sqlite::{delete_db, search, upsert};
use criterion::{async_executor::FuturesExecutor, criterion_group, criterion_main, Criterion};
use futures::executor::block_on;
use rand::SeedableRng;

fn prepare_locations_and_words(number: i64) -> HashMap<IndexedValue, HashSet<Keyword>> {
    let mut locations_and_words = HashMap::new();
    for idx in 0..number {
        let mut words = HashSet::new();
        words.insert(Keyword::from(format!("first_name_{idx}").as_bytes()));
        words.insert(Keyword::from(format!("name_{idx}").as_bytes()));

        locations_and_words.insert(
            IndexedValue::Location(Location::from(idx.to_be_bytes().as_slice())),
            words.clone(),
        );
    }
    locations_and_words
}
fn prepare_keywords(number: i64) -> HashSet<Keyword> {
    let mut keywords = HashSet::new();
    for idx in 0..number {
        keywords.insert(Keyword::from(format!("name_{idx}").as_str()));
    }
    keywords
}

fn bench_search(c: &mut Criterion) {
    //
    // Generate new dataset
    //
    let mut group = c.benchmark_group("search");

    let mut rng = CsRng::from_entropy();
    let label = Label::random(&mut rng);
    let master_key = KeyingMaterial::new(&mut rng);
    let locations_and_words = prepare_locations_and_words(10000);

    //
    // Prepare indexes to be search
    //
    let mut findex = FindexInMemory::default();
    block_on(findex.upsert(locations_and_words, &master_key, &label)).expect("msg");

    //
    // Search 1 word
    //
    let bulk_words = HashSet::from_iter([Keyword::from("name_0")]);
    group.bench_function("Searching 1 word", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            findex
                .clone()
                .search(
                    &bulk_words,
                    &master_key,
                    &label,
                    usize::MAX,
                    usize::MAX,
                    SECURE_FETCH_CHAINS_BATCH_SIZE,
                    0,
                )
                .await
                .expect("search failed");
        });
    });

    //
    // Search 10 words
    //
    let keywords = prepare_keywords(10);
    group.bench_function("Searching 10 words", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            findex
                .clone()
                .search(
                    &keywords,
                    &master_key,
                    &label,
                    usize::MAX,
                    usize::MAX,
                    SECURE_FETCH_CHAINS_BATCH_SIZE,
                    0,
                )
                .await
                .expect("search failed");
        });
    });
    //
    // Search 100 words
    //
    let keywords = prepare_keywords(100);
    group.bench_function("Searching 100 words", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            findex
                .clone()
                .search(
                    &keywords,
                    &master_key,
                    &label,
                    usize::MAX,
                    usize::MAX,
                    SECURE_FETCH_CHAINS_BATCH_SIZE,
                    0,
                )
                .await
                .expect("search failed");
        });
    });
    //
    // Search 1000 words
    //
    let keywords = prepare_keywords(1000);
    group.bench_function("Searching 1000 words", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            findex
                .clone()
                .search(
                    &keywords,
                    &master_key,
                    &label,
                    usize::MAX,
                    usize::MAX,
                    SECURE_FETCH_CHAINS_BATCH_SIZE,
                    0,
                )
                .await
                .expect("search failed");
        });
    });
    group.finish();
}

fn bench_upsert(c: &mut Criterion) {
    //
    // Generate new dataset
    //
    let mut group = c.benchmark_group("upsert");

    let mut rng = CsRng::from_entropy();
    let label = Label::random(&mut rng);
    let master_key = KeyingMaterial::new(&mut rng);

    let locations_and_words = prepare_locations_and_words(10);
    group.bench_function("Indexing 20 keywords", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            FindexInMemory::default()
                .upsert(locations_and_words.clone(), &master_key, &label)
                .await
                .expect("upsert failed");
        });
    });
    let locations_and_words = prepare_locations_and_words(100);
    group.bench_function("Indexing 200 keywords", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            FindexInMemory::default()
                .upsert(locations_and_words.clone(), &master_key, &label)
                .await
                .expect("upsert failed");
        });
    });
    let locations_and_words = prepare_locations_and_words(1000);
    group.bench_function("Indexing 2000 keywords", |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            FindexInMemory::default()
                .upsert(locations_and_words.clone(), &master_key, &label)
                .await
                .expect("upsert failed");
        });
    });

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(5000);
    targets =
        bench_search,
        bench_upsert,
);

criterion_main!(benches);
