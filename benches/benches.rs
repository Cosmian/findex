#[cfg(not(feature = "in_memory"))]
compile_error!("Benches require the `in_memory` feature.");

use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::CsRng;
use cosmian_findex::{
    in_memory_example::FindexInMemory, FindexSearch, FindexUpsert, IndexedValue, KeyingMaterial,
    Keyword, Label, Location,
};
use criterion::{criterion_group, criterion_main, Criterion};
use futures::executor::block_on;
use rand::SeedableRng;

fn prepare_locations_and_words(number: usize) -> HashMap<IndexedValue, HashSet<Keyword>> {
    let mut locations_and_words = HashMap::with_capacity(number);
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

fn prepare_keywords(number: usize) -> HashSet<Keyword> {
    let mut keywords = HashSet::with_capacity(number);
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
    block_on(findex.upsert(locations_and_words, HashMap::new(), &master_key, &label)).expect("msg");

    println!("Entry Table length: {}", findex.entry_table_len());
    println!("Entry Table size: {}", findex.entry_table_size());
    println!("Chain Table length: {}", findex.chain_table_len());
    println!("Chain Table size: {}", findex.chain_table_size());

    for power in 0..=3 {
        let n_keywords = 10usize.pow(power);
        let keywords = prepare_keywords(n_keywords);
        group.bench_function(format!("Searching {n_keywords} keyword(s)"), |b| {
            b.iter(|| {
                block_on(findex.search(&keywords, &master_key, &label, usize::MAX, usize::MAX, 0))
                    .expect("search failed");
            });
        });
    }
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

    for power in 1..=3 {
        let n_keywords = 10usize.pow(power);
        let locations_and_words = prepare_locations_and_words(n_keywords);
        group.bench_function(format!("Upserting {n_keywords} keyword(s)"), |b| {
            b.iter(|| {
                block_on(FindexInMemory::default().upsert(
                    locations_and_words.clone(),
                    HashMap::new(),
                    &master_key,
                    &label,
                ))
                .expect("upsert failed");
            });
        });
    }
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
