// It is too much trouble to deactivate everything if none of the features are
// activated.
#![allow(unused_imports, unused_variables, unused_mut, dead_code)]

use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
use cosmian_findex::{ADDRESS_LENGTH, Address, InMemory, WORD_LENGTH};
use cosmian_findex::{
    bench_memory_contention, bench_memory_insert_multiple_bindings, bench_memory_one_to_many,
    bench_memory_search_multiple_bindings, bench_memory_search_multiple_keywords,
};
use criterion::{Criterion, criterion_group, criterion_main};

// Number of points in each graph.
const N_PTS: usize = 9;

fn bench_search_multiple_bindings(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    bench_memory_search_multiple_bindings(
        "in-memory",
        N_PTS,
        async || InMemory::default(),
        c,
        &mut rng,
    );
}

fn bench_search_multiple_keywords(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    bench_memory_search_multiple_keywords(
        "in-memory",
        N_PTS,
        async || InMemory::default(),
        c,
        &mut rng,
    );
}

fn bench_insert_multiple_bindings(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    bench_memory_insert_multiple_bindings(
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
}

fn bench_contention(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();

    bench_memory_contention(
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
}

criterion_group!(
    name    = benches;
    config  = Criterion::default();
    targets =
    bench_search_multiple_bindings,
    bench_search_multiple_keywords,
    bench_insert_multiple_bindings,
    bench_contention,
);

criterion_main!(benches);
