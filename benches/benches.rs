#![allow(dead_code, unused)]
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use cosmian_crypto_core::{
    reexport::rand_core::{CryptoRngCore, SeedableRng},
    CsRng, Secret,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use findex_bis::{dummy_decode, dummy_encode, Findex, Index, KvStore};
use futures::executor::block_on;

fn build_benchmarking_index(rng: &mut impl CryptoRngCore) -> Vec<([u8; 8], HashSet<[u8; 8]>)> {
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

fn bench_search(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let index = build_benchmarking_index(&mut rng);
    let seed = Secret::random(&mut rng);
    let stm = KvStore::default();
    let findex = Findex::new(
        seed,
        Arc::new(Mutex::new(rng)),
        stm,
        dummy_encode,
        dummy_decode,
    );
    block_on(findex.insert(index.clone().into_iter())).unwrap();

    {
        let mut group = c.benchmark_group("Multiple bindings search");
        for (i, (kw, vals)) in index.clone().into_iter().enumerate() {
            let n = 10i32.pow(i as u32) as usize;
            group.bench_function(BenchmarkId::from_parameter(n), |b| {
                b.iter(|| {
                    let res = block_on(findex.search([kw].into_iter())).expect("search failed");
                });
            });
        }
    }

    {
        let mut group = c.benchmark_group("Multiple keywords search (1 binding)");
        for i in 0..=4 {
            let n = 10i32.pow(i) as usize;
            let kws = vec![index[0].0; n];
            group.bench_function(BenchmarkId::from_parameter(n), |b| {
                b.iter_batched(
                    || kws.clone(),
                    |kws| {
                        block_on(findex.search(kws.into_iter())).expect("search failed");
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    }

    {
        let mut group = c.benchmark_group("Multiple keywords search (1000 bindings)");
        for i in 0..=4 {
            let n = 10i32.pow(i) as usize;
            let kws = vec![index[3].0; n];
            group.bench_function(BenchmarkId::from_parameter(n), |b| {
                b.iter_batched(
                    || kws.clone(),
                    |kws| {
                        block_on(findex.search(kws.into_iter())).expect("search failed");
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    }
}

fn bench_insert(c: &mut Criterion) {
    let mut rng = CsRng::from_entropy();
    let index = build_benchmarking_index(&mut rng);
    let seed = Secret::random(&mut rng);
    {
        let mut group = c.benchmark_group("Multiple bindings insert (same keyword)");
        for (i, (kw, vals)) in index.clone().into_iter().enumerate() {
            let n = 10i32.pow(i as u32) as usize;
            group.bench_function(BenchmarkId::from_parameter(n), |b| {
                b.iter_batched(
                    || {
                        let rng = CsRng::from_entropy();
                        let seed = seed.clone();
                        let vals = vals.clone();
                        (seed, rng, kw, vals)
                    },
                    |(seed, rng, kw, vals)| {
                        let findex = Findex::new(
                            seed,
                            Arc::new(Mutex::new(rng)),
                            KvStore::default(),
                            dummy_encode,
                            dummy_decode,
                        );
                        block_on(findex.insert([(kw, vals)].into_iter())).expect("search failed");
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    }
}

criterion_group!(
    name    = benches;
    config  = Criterion::default().sample_size(5000);
    targets = bench_search, bench_insert,
);

criterion_main!(benches);
