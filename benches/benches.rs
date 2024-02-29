use cosmian_crypto_core::CsRng;
use cosmian_findex::{mm, Data, InMemoryDb, Index, Keyword, Mm, Set, UserKey};
use criterion::{criterion_group, criterion_main, Criterion};
use futures::executor::block_on;
use rand::SeedableRng;

fn prepare_locations_and_words(number: usize) -> Mm<Keyword, Data> {
    let mut index = mm!();
    for idx in 0..number {
        index.insert(
            format!("first_name_{idx}").as_bytes().to_vec().into(),
            vec![idx.to_be_bytes().to_vec().into()],
        );
        index.insert(
            format!("name_{idx}").as_bytes().to_vec().into(),
            vec![idx.to_be_bytes().to_vec().into()],
        );
    }
    index
}

fn prepare_keywords(number: usize) -> Set<Keyword> {
    let mut keywords = Set::with_capacity(number);
    for idx in 0..number {
        keywords.insert(Keyword::from(format!("name_{idx}").as_str()));
    }
    keywords
}

fn bench_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("search");

    //
    // Generate new dataset
    //
    let locations_and_words = prepare_locations_and_words(10000);

    //
    // Prepare indexes to be searched
    //
    let mut rng = CsRng::from_entropy();
    let key = UserKey::random(&mut rng);
    let entry_table = InMemoryDb::default();
    let chain_table = InMemoryDb::default();

    let index = Index::new(&key, entry_table.clone(), chain_table.clone()).unwrap();

    block_on(index.add(locations_and_words)).unwrap();

    println!("Entry Table length: {}", entry_table.len());
    println!("Entry Table length: {}", entry_table.size());
    println!("Chain Table length: {}", chain_table.len());
    println!("Chain Table length: {}", chain_table.size());

    for power in 0..=3 {
        let n_keywords = 10usize.pow(power);
        let keywords = prepare_keywords(n_keywords);
        group.bench_function(format!("Searching {n_keywords} keyword(s)"), |b| {
            b.iter_batched(
                || keywords.clone(),
                |keywords| {
                    block_on(index.search::<_, Data>(keywords)).expect("search failed");
                },
                criterion::BatchSize::SmallInput,
            );
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
    let key = UserKey::random(&mut rng);
    let mut entry_table = InMemoryDb::default();
    let mut chain_table = InMemoryDb::default();

    let index = Index::new(&key, entry_table.clone(), chain_table.clone()).unwrap();

    for power in 1..=3 {
        let n_keywords = 10usize.pow(power);
        let locations_and_words = prepare_locations_and_words(n_keywords);
        group.bench_function(format!("Upserting {n_keywords} keyword(s)"), |b| {
            b.iter_batched(
                || {
                    entry_table.flush();
                    chain_table.flush();
                    locations_and_words.clone()
                },
                |locations_and_words| {
                    block_on(index.add(locations_and_words)).expect("upsert failed");
                },
                criterion::BatchSize::SmallInput,
            );
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
