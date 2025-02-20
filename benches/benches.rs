use std::{collections::HashSet, time::Duration};

use cosmian_findex::{
    Findex, InMemory, IndexADT, MemoryADT, MemoryEncryptionLayer, Op, Secret, WORD_LENGTH,
    dummy_decode, dummy_encode,
};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use futures::{executor::block_on, future::join_all};
use lazy_static::lazy_static;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

lazy_static! {
    static ref scale: Vec<f32> = make_scale(0, 4, 20);
}

fn make_scale(start: usize, stop: usize, n: usize) -> Vec<f32> {
    let step = ((stop - start) as f32) / n as f32;
    let mut points = Vec::with_capacity(n);
    for i in 0..=n {
        points.push(start as f32 + i as f32 * step);
    }
    points
}

/// Builds an index that associates each `kw_i` to x values, both random 64-bit
/// values.
fn build_benchmarking_bindings_index(rng: &mut impl CryptoRng) -> Vec<([u8; 8], HashSet<[u8; 8]>)> {
    scale
        .iter()
        .map(|i| {
            let kw = rng.next_u64().to_be_bytes();
            let vals = (0..10f32.powf(*i).ceil() as usize)
                .map(|_| rng.next_u64().to_be_bytes())
                .collect::<HashSet<_>>();
            (kw, vals)
        })
        .collect()
}

/// Builds an index that associates 10^3 `kw_i` to a single value, both random
/// 64-bit values.
fn build_benchmarking_keywords_index(rng: &mut impl CryptoRng) -> Vec<([u8; 8], HashSet<[u8; 8]>)> {
    (0..10usize.pow(3))
        .map(|_| {
            let kw = rng.next_u64().to_be_bytes();
            let val = rng.next_u64().to_be_bytes();
            (kw, HashSet::from([val]))
        })
        .collect()
}

fn bench_search_multiple_bindings(c: &mut Criterion) {
    let mut rng = ChaChaRng::from_os_rng();
    let seed = Secret::random(&mut rng);
    let ctx_memory = MemoryEncryptionLayer::new(&seed, InMemory::default());
    let index = build_benchmarking_bindings_index(&mut rng);
    let findex = Findex::new(ctx_memory, dummy_encode::<WORD_LENGTH, _>, dummy_decode);
    index
        .iter()
        .cloned()
        .for_each(|(kw, vs)| block_on(findex.insert(kw, vs)).unwrap());

    let mut group = c.benchmark_group("Multiple bindings search (1 keyword)");
    for (kw, vals) in index.clone().into_iter() {
        group.bench_function(BenchmarkId::from_parameter(vals.len()), |b| {
            b.iter_batched(
                || [kw].into_iter(),
                |kws| {
                    kws.for_each(|kw| {
                        block_on(findex.search(&kw)).expect("search failed");
                    });
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
}

fn bench_search_multiple_keywords(c: &mut Criterion) {
    let mut rng = ChaChaRng::from_os_rng();

    let index = build_benchmarking_keywords_index(&mut rng);

    let seed = Secret::random(&mut rng);
    let ptx_memory = InMemory::default();
    let ctx_memory = MemoryEncryptionLayer::new(&seed, ptx_memory.clone());
    let findex = Findex::new(
        ctx_memory.clone(),
        dummy_encode::<WORD_LENGTH, _>,
        dummy_decode,
    );

    index
        .iter()
        .cloned()
        .for_each(|(kw, vs)| block_on(findex.insert(kw, vs)).unwrap());

    // Reference timings
    {
        let mut group = c.benchmark_group("retrieving words from memory");
        for i in scale.iter() {
            let n = 10f32.powf(*i).ceil() as usize;
            group.bench_function(BenchmarkId::from_parameter(n), |b| {
                // Attempts to bench all external costs (somehow, cloning the keywords impacts
                // the benches).
                b.iter_batched(
                    || {
                        ptx_memory
                            .clone()
                            .into_iter()
                            .map(|(a, _)| a)
                            .take(n)
                            .collect::<Vec<_>>()
                    },
                    |addresses| {
                        block_on(ptx_memory.batch_read(addresses)).expect("batch read failed")
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    }
    // Benches
    {
        let mut group = c.benchmark_group("Multiple keywords search (1 binding)");
        for i in scale.iter() {
            let n = 10f32.powf(*i).ceil() as usize;
            group.bench_function(BenchmarkId::from_parameter(n), |b| {
                b.iter_batched(
                    || {
                        // Using .cloned() instead of .clone() reduces the overhead (maybe because
                        // it only clones what is needed)
                        index.iter().map(|(kw, _)| kw).take(n).cloned()
                    },
                    |kws| {
                        kws.for_each(|kw| {
                            block_on(findex.search(&kw)).expect("search failed");
                        });
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    }
}

fn bench_insert_multiple_bindings(c: &mut Criterion) {
    let mut rng = ChaChaRng::from_os_rng();

    let index = build_benchmarking_bindings_index(&mut rng);
    let n_max = 10usize.pow(3);

    // Reference: write one word per value inserted.
    {
        let mut group = c.benchmark_group("write n words to memory");
        for (_, vals) in index.clone().into_iter() {
            let stm = InMemory::with_capacity(n_max + 1);
            group
                .bench_function(BenchmarkId::from_parameter(vals.len()), |b| {
                    b.iter_batched(
                        || {
                            let vals = vals.clone();
                            let words = dummy_encode::<WORD_LENGTH, _>(Op::Insert, vals).unwrap();
                            words
                                .into_iter()
                                .enumerate()
                                .map(|(i, w)| ([i; 16], w))
                                .collect::<Vec<_>>()
                        },
                        |bindings| {
                            block_on(stm.guarded_write(([0; 16], None), bindings))
                                .expect("search failed");
                        },
                        criterion::BatchSize::SmallInput,
                    );
                })
                .measurement_time(Duration::from_secs(60));
        }
    }
    // Bench it
    {
        let mut group = c.benchmark_group("Multiple bindings insert (same keyword)");
        for (kw, vals) in index.clone().into_iter() {
            let seed = Secret::random(&mut rng);
            let ptx_memory = InMemory::with_capacity(n_max + 1);
            let ctx_memory = MemoryEncryptionLayer::new(&seed, ptx_memory.clone());
            let findex = Findex::new(
                ctx_memory.clone(),
                dummy_encode::<WORD_LENGTH, _>,
                dummy_decode,
            );
            group
                .bench_function(BenchmarkId::from_parameter(vals.len()), |b| {
                    b.iter_batched(
                        || {
                            ptx_memory.clear();
                            [(kw, vals.clone())].into_iter()
                        },
                        |bindings| {
                            bindings.for_each(|(kw, vs)| {
                                block_on(findex.insert(kw, vs)).expect("search failed")
                            });
                        },
                        criterion::BatchSize::SmallInput,
                    );
                })
                .measurement_time(Duration::from_secs(60));
        }
    }
}

fn bench_insert_multiple_keywords(c: &mut Criterion) {
    let mut rng = ChaChaRng::from_os_rng();

    // Reference: write one word per value inserted.
    {
        let mut group = c.benchmark_group("write 2n words to memory");
        for i in scale.iter() {
            let n = 10f32.powf(*i).ceil() as usize;
            let stm = InMemory::with_capacity(2 * n);
            group
                .bench_function(BenchmarkId::from_parameter(n), |b| {
                    b.iter_batched(
                        || {
                            stm.clear();
                            (0..2 * n)
                                .map(|_| {
                                    let mut a = [0; 16];
                                    let mut w = [0; WORD_LENGTH];
                                    rng.fill_bytes(&mut a);
                                    rng.fill_bytes(&mut w);
                                    (a, w)
                                })
                                .collect::<Vec<_>>()
                        },
                        |bindings| {
                            block_on(stm.guarded_write(([0; 16], None), bindings))
                                .expect("search failed");
                        },
                        criterion::BatchSize::SmallInput,
                    );
                })
                .measurement_time(Duration::from_secs(60));
        }
    }
    // Bench it
    {
        let mut group = c.benchmark_group("Multiple keywords insert (one binding each)");
        for i in scale.iter() {
            let n = 10f32.powf(*i).ceil() as usize;
            let seed = Secret::random(&mut rng);
            let ptx_memory = InMemory::with_capacity(2 * n);
            let ctx_memory = MemoryEncryptionLayer::new(&seed, ptx_memory.clone());
            let findex = Findex::new(
                ctx_memory.clone(),
                dummy_encode::<WORD_LENGTH, _>,
                dummy_decode,
            );

            group
                .bench_function(BenchmarkId::from_parameter(n), |b| {
                    b.iter_batched(
                        || {
                            ptx_memory.clear();
                            (0..n)
                                .map(|_| {
                                    (
                                        rng.next_u64().to_be_bytes(),
                                        HashSet::<[u8; 8]>::from_iter([rng
                                            .next_u64()
                                            .to_be_bytes()]),
                                    )
                                })
                                .collect::<Vec<_>>()
                                .into_iter()
                        },
                        |bindings| {
                            bindings.for_each(|(kw, vs)| {
                                block_on(findex.insert(kw, vs)).expect("insert failed");
                            });
                        },
                        criterion::BatchSize::SmallInput,
                    );
                })
                .measurement_time(Duration::from_secs(60));
        }
    }
}

fn bench_contention(c: &mut Criterion) {
    const N_BINDINGS: usize = 100;
    const N_CLIENTS: usize = 8;
    let mut rng = ChaChaRng::from_os_rng();
    let kws = (0..N_CLIENTS)
        .map(|_| rng.next_u64().to_be_bytes())
        .collect::<Vec<_>>();

    // Reference: parallel clients.
    {
        let mut group =
            c.benchmark_group("Parallel clients ({N_BINDINGS} binding, different keywords)");
        for i in 1..=N_CLIENTS {
            let seed = Secret::random(&mut rng);
            let ptx_memory = InMemory::with_capacity(N_BINDINGS * i + 1);
            let ctx_memory = MemoryEncryptionLayer::new(&seed, ptx_memory.clone());
            let findex = Findex::new(
                ctx_memory.clone(),
                dummy_encode::<WORD_LENGTH, _>,
                dummy_decode,
            );
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(i)
                .enable_all()
                .build()
                .unwrap();

            let instances = (0..i).map(|_| findex.clone()).collect::<Vec<_>>();
            let bindings = kws
                .clone()
                .into_iter()
                .map(|kw| {
                    (
                        kw, // All clients use a different keyword.
                        HashSet::<[u8; 8]>::from_iter(
                            (0..N_BINDINGS).map(|_| rng.next_u64().to_be_bytes()),
                        ),
                    )
                })
                .collect::<Vec<_>>();

            group
                .bench_function(BenchmarkId::from_parameter(i), |b| {
                    b.iter_batched(
                        || {
                            ptx_memory.clear();
                            instances.clone().into_iter().zip(bindings.clone())
                        },
                        |iterator| {
                            runtime.block_on(async {
                                join_all(iterator.map(|(findex, (kw, vs))| {
                                    tokio::spawn(async move { findex.insert(kw, vs).await })
                                }))
                                .await
                            })
                        },
                        criterion::BatchSize::SmallInput,
                    );
                })
                .measurement_time(Duration::from_secs(60));
        }
    }

    // Concurrent clients.
    {
        let mut group = c.benchmark_group("Concurrent clients (single binding, same keyword)");
        for i in 1..=N_CLIENTS {
            let seed = Secret::random(&mut rng);
            let ptx_memory = InMemory::with_capacity(N_BINDINGS * i + 1);
            let ctx_memory = MemoryEncryptionLayer::new(&seed, ptx_memory.clone());
            let findex = Findex::new(
                ctx_memory.clone(),
                dummy_encode::<WORD_LENGTH, _>,
                dummy_decode,
            );
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(i)
                .enable_all()
                .build()
                .unwrap();

            let instances = (0..i).map(|_| findex.clone()).collect::<Vec<_>>();
            let bindings = (0..i)
                .map(|_| {
                    (
                        kws[0], // All clients use the same keyword
                        HashSet::<[u8; 8]>::from_iter(
                            (0..N_BINDINGS).map(|_| rng.next_u64().to_be_bytes()),
                        ),
                    )
                })
                .collect::<Vec<_>>();

            group
                .bench_function(BenchmarkId::from_parameter(i), |b| {
                    b.iter_batched(
                        || {
                            ptx_memory.clear();
                            instances.clone().into_iter().zip(bindings.clone())
                        },
                        |iterator| {
                            runtime.block_on(async {
                                join_all(iterator.map(|(findex, (kw, vs))| {
                                    tokio::spawn(async move { findex.insert(kw, vs).await })
                                }))
                                .await
                            })
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
    config  = Criterion::default().sample_size(5000).measurement_time(Duration::from_secs(60));
    targets = bench_contention,
              bench_search_multiple_bindings, bench_search_multiple_keywords,
              bench_insert_multiple_bindings, bench_insert_multiple_keywords,
);

criterion_main!(benches);
