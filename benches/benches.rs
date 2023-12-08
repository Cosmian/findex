use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::CsRng;
use cosmian_findex::{
    ChainTable, Data, DxEnc, EntryTable, Findex, InMemoryDb, Index, IndexedValue,
    IndexedValueToKeywordsMap, Keyword, Keywords, Label,
};
use criterion::{criterion_group, criterion_main, Criterion};
use futures::executor::block_on;
use rand::SeedableRng;

fn prepare_locations_and_words(number: usize) -> IndexedValueToKeywordsMap {
    let mut locations_and_words = HashMap::with_capacity(number);
    for idx in 0..number {
        let mut words = HashSet::new();
        words.insert(Keyword::from(format!("first_name_{idx}").as_bytes()));
        words.insert(Keyword::from(format!("name_{idx}").as_bytes()));
        locations_and_words.insert(
            IndexedValue::Data(Data::from(idx.to_be_bytes().as_slice())),
            Keywords::from(words.clone()),
        );
    }
    IndexedValueToKeywordsMap::from(locations_and_words)
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
    let locations_and_words = prepare_locations_and_words(10000);

    //
    // Prepare indexes to be search
    //
    let findex = Findex::new(
        EntryTable::setup(InMemoryDb::default()),
        ChainTable::setup(InMemoryDb::default()),
    );

    let key = findex.keygen();
    block_on(findex.add(&key, &label, locations_and_words)).expect("msg");

    println!(
        "Entry Table length: {}",
        findex.findex_graph.findex_mm.entry_table.len()
    );
    println!(
        "Entry Table length: {}",
        findex.findex_graph.findex_mm.entry_table.size()
    );
    println!(
        "Chain Table length: {}",
        findex.findex_graph.findex_mm.chain_table.len()
    );
    println!(
        "Chain Table length: {}",
        findex.findex_graph.findex_mm.chain_table.size()
    );

    for power in 0..=3 {
        let n_keywords = 10usize.pow(power);
        let keywords = prepare_keywords(n_keywords);
        group.bench_function(format!("Searching {n_keywords} keyword(s)"), |b| {
            b.iter(|| {
                block_on(findex.search(
                    &key,
                    &label,
                    Keywords::from(keywords.clone()),
                    &|_| async { Ok(false) },
                ))
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
    let mut findex = Findex::new(
        EntryTable::setup(InMemoryDb::default()),
        ChainTable::setup(InMemoryDb::default()),
    );
    let key = findex.keygen();

    for power in 1..=3 {
        let n_keywords = 10usize.pow(power);
        let locations_and_words = prepare_locations_and_words(n_keywords);
        group.bench_function(format!("Upserting {n_keywords} keyword(s)"), |b| {
            b.iter(|| {
                block_on(findex.add(&key, &label, locations_and_words.clone()))
                    .expect("upsert failed");
                findex.findex_graph.findex_mm.entry_table.0.flush();
                findex.findex_graph.findex_mm.chain_table.0.flush();
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
