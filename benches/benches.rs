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

fn bench_search(c: &mut Criterion) {
    fn build_benchmarking_index(rng: &mut impl CryptoRngCore) -> Vec<([u8; 8], HashSet<[u8; 8]>)> {
        (0..6)
            .map(|i| {
                let kw = rng.next_u64().to_be_bytes();
                let vals = (1..10_i64.pow(i) as usize)
                    .map(|_| rng.next_u64().to_be_bytes())
                    .collect::<HashSet<_>>();
                (kw, vals)
            })
            .collect()
    }

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
    findex.insert(index.clone().into_iter());

    {
        let mut group = c.benchmark_group("Multiple bindings search");
        for (i, (kw, _)) in index.clone().into_iter().enumerate() {
            let n = 10i32.pow(i as u32) as usize;
            group.bench_function(BenchmarkId::from_parameter(n), |b| {
                b.iter(|| {
                    block_on(findex.search([kw].into_iter())).expect("search failed");
                });
            });
        }
    }

    {
        let mut group = c.benchmark_group("Multiple keywords search (1 binding)");
        for i in 0..4 {
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
        for i in 0..4 {
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

criterion_group!(
    name    = benches;
    config  = Criterion::default().sample_size(5000);
    targets = bench_search,
);

criterion_main!(benches);
