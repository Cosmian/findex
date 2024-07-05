#![allow(dead_code, unused)]
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use cosmian_crypto_core::{
    reexport::rand_core::{CryptoRngCore, RngCore, SeedableRng},
    CsRng, Secret,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use findex_bis::{dummy_decode, dummy_encode, Findex, IndexADT, KvStore, MemoryADT, Op};
use futures::executor::block_on;

/// Builds an index that associates each `kw_i` to `10^i` values, both random 64-bit values.
fn build_benchmarking_bindings_index(
    rng: &mut impl CryptoRngCore,
) -> Vec<([u8; 8], HashSet<[u8; 8]>)> {
    (0..4)
        .map(|i| {
            let kw = rng.next_u64().to_be_bytes();
            let vals = (0..10_i64.pow(i) as usize)
                .map(|_| rng.next_u64().to_be_bytes())
                .collect::<HashSet<_>>();
            (kw, vals)
        })
        .collect()
}

/// Builds an index that associates 10^3 `kw_i` to a single value, both random 64-bit values.
fn build_benchmarking_keywords_index(
    rng: &mut impl CryptoRngCore,
) -> Vec<([u8; 8], HashSet<[u8; 8]>)> {
    (0..10usize.pow(3))
        .map(|_| {
            let kw = rng.next_u64().to_be_bytes();
            let val = rng.next_u64().to_be_bytes();
            (kw, HashSet::from([val]))
        })
        .collect()
}

fn bench_search(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let seed = Secret::random(&mut rng);
    // Bench the impact of the binding multiplicity.
    {
        let stm = KvStore::default();
        let index = build_benchmarking_bindings_index(&mut rng);
        let findex = Findex::new(
            seed.clone(),
            Arc::new(Mutex::new(rng.clone())),
            stm,
            dummy_encode::<16, _>,
            dummy_decode,
        );
        block_on(findex.insert(index.clone().into_iter())).unwrap();

        let mut group = c.benchmark_group("Multiple bindings search (1 keyword)");
        for (i, (kw, vals)) in index.clone().into_iter().enumerate() {
            let n = 10i32.pow(i as u32) as usize;
            group.bench_function(BenchmarkId::from_parameter(n), |b| {
                b.iter_batched(
                    || [kw].into_iter(),
                    |kws| {
                        block_on(findex.search(kws)).expect("search failed");
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    }

    // Bench the impact of the keyword multiplicity.
    {
        let stm = KvStore::default();
        let index = build_benchmarking_keywords_index(&mut rng);
        let findex = Findex::new(
            seed,
            Arc::new(Mutex::new(rng)),
            stm.clone(),
            dummy_encode::<16, _>,
            dummy_decode,
        );
        block_on(findex.insert(index.clone().into_iter())).unwrap();
        let mut group = c.benchmark_group("Multiple keywords search (1 binding)");
        for i in 0..4 {
            let n = 10i32.pow(i) as usize;
            group.bench_function(format!("reading {n} words from memory"), |b| {
                // Attempts to bench all external costs (somehow, cloning the keywords impacts the
                // benches).
                b.iter_batched(
                    || {
                        stm.clone()
                            .into_iter()
                            .map(|(a, w)| a)
                            .take(n)
                            .collect::<Vec<_>>()
                    },
                    |addresses| block_on(stm.batch_read(addresses)).expect("batch read failed"),
                    criterion::BatchSize::SmallInput,
                );
            });
            // Go bench it.
            group.bench_function(BenchmarkId::from_parameter(n), |b| {
                b.iter_batched(
                    || {
                        // Using .cloned() instead of .clone() reduces the overhead (maybe because it
                        // only clones what is needed)
                        index.iter().map(|(kw, val)| kw).take(n).cloned()
                    },
                    |kws| {
                        block_on(findex.search(kws)).expect("search failed");
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    }
}

fn bench_insert(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let seed = Secret::random(&mut rng);

    // Bench the impact of the binding multiplicity.
    {
        let index = build_benchmarking_bindings_index(&mut rng);
        let mut group = c.benchmark_group("Multiple bindings insert (same keyword)");
        for (i, (kw, vals)) in index.clone().into_iter().enumerate() {
            let n = 10i32.pow(i as u32) as usize;
            group
                .bench_function(format!("inserting {n} words to memory"), |b| {
                    b.iter_batched(
                        || {
                            let rng = CsRng::from_entropy();
                            let seed = seed.clone();
                            let vals = vals.clone();
                            let stm = KvStore::default();
                            let words = dummy_encode::<16, _>(Op::Insert, vals).unwrap();
                            let bindings = words
                                .into_iter()
                                .enumerate()
                                .map(|(i, w)| ([i; 16], w))
                                .collect::<Vec<_>>();
                            (stm, bindings)
                        },
                        |(stm, bindings)| {
                            block_on(stm.guarded_write(([0; 16], None), bindings))
                                .expect("search failed");
                        },
                        criterion::BatchSize::SmallInput,
                    );
                })
                .measurement_time(Duration::from_secs(60));
            group
                .bench_function(BenchmarkId::from_parameter(n), |b| {
                    b.iter_batched(
                        || {
                            let seed = seed.clone();
                            let vals = vals.clone();
                            let findex = Findex::new(
                                seed,
                                Arc::new(Mutex::new(rng.clone())),
                                KvStore::default(),
                                dummy_encode::<16, _>,
                                dummy_decode,
                            );
                            let bindings = [(kw, vals)].into_iter();
                            (findex, bindings)
                        },
                        |(findex, bindings)| {
                            block_on(findex.insert(bindings)).expect("search failed");
                        },
                        criterion::BatchSize::SmallInput,
                    );
                })
                .measurement_time(Duration::from_secs(60));
        }
    }

    // Bench the impact of the keyword multiplicity.
    {
        let mut group = c.benchmark_group("Multiple keywords insert (one binding each)");
        for i in 0..4 {
            let n = 10usize.pow(i);
            group
                .bench_function(format!("inserting {n} words to memory"), |b| {
                    b.iter_batched(
                        || {
                            let seed = seed.clone();
                            let stm = KvStore::default();
                            let bindings = (0..2 * n)
                                .map(|_| {
                                    let mut a = [0; 16];
                                    let mut w = [0; 16];
                                    rng.fill_bytes(&mut a);
                                    rng.fill_bytes(&mut w);
                                    (a, w)
                                })
                                .collect::<Vec<_>>();
                            (stm, bindings)
                        },
                        |(stm, bindings)| {
                            block_on(stm.guarded_write(([0; 16], None), bindings))
                                .expect("search failed");
                        },
                        criterion::BatchSize::SmallInput,
                    );
                })
                .measurement_time(Duration::from_secs(60));
            group
                .bench_function(BenchmarkId::from_parameter(n), |b| {
                    b.iter_batched(
                        || {
                            let findex = Findex::new(
                                seed.clone(),
                                Arc::new(Mutex::new(rng.clone())),
                                KvStore::default(),
                                dummy_encode::<16, _>,
                                dummy_decode,
                            );
                            let bindings = (0..n)
                                .map(|_| {
                                    (
                                        rng.next_u64().to_be_bytes(),
                                        HashSet::from_iter([rng.next_u64().to_be_bytes()]),
                                    )
                                })
                                .collect::<Vec<_>>();
                            (findex, bindings.into_iter())
                        },
                        |(findex, bindings)| {
                            block_on(findex.insert(bindings)).expect("search failed");
                        },
                        criterion::BatchSize::SmallInput,
                    );
                })
                .measurement_time(Duration::from_secs(60));
        }
    }
}

criterion_group!(
    name    = benches;
    config  = Criterion::default().sample_size(5000);
    targets = bench_search, bench_insert,
);

criterion_main!(benches);
