use crate::{
    ADDRESS_LENGTH, Address, Findex, IndexADT, MemoryADT, MemoryEncryptionLayer, WORD_LENGTH,
    dummy_decode, dummy_encode,
};
use cosmian_crypto_core::{Secret, reexport::rand_core::CryptoRngCore};
use criterion::{BenchmarkId, Criterion};
use futures::future::join_all;
use std::{collections::HashSet, fmt::Debug, sync::Arc};
use tokio::runtime::{Builder, Runtime};

const MAX_VAL: usize = 1_000;

fn make_scale(start: usize, stop: usize, n: usize) -> impl Iterator<Item = f32> {
    let step = (stop - start) as f32 / n as f32;
    (0..=n).map(move |i| (i as f32).mul_add(step, start as f32))
}

/// Builds an index that associates each `kw_i` to 10^x_i random 64-bit values,
/// where x_i is the ith scale value.
fn build_benchmarking_bindings_index(
    n: usize,
    rng: &mut impl CryptoRngCore,
) -> Vec<([u8; 8], HashSet<[u8; 8]>)> {
    make_scale(1, MAX_VAL, n)
        .map(|i| {
            let kw = rng.next_u64().to_be_bytes();
            let vs = (0..i.ceil() as usize)
                .map(|_| rng.next_u64().to_be_bytes())
                .collect::<HashSet<_>>();
            (kw, vs)
        })
        .collect()
}

/// Builds an index that associates 10^3 `kw_i` to a single value, both random
/// 64-bit values.
fn build_benchmarking_keywords_index(
    rng: &mut impl CryptoRngCore,
) -> Vec<([u8; 8], HashSet<[u8; 8]>)> {
    (0..MAX_VAL)
        .map(|_| {
            let kw = rng.next_u64().to_be_bytes();
            let val = rng.next_u64().to_be_bytes();
            (kw, HashSet::from([val]))
        })
        .collect()
}

/// Benches the time required to search for a given keyword, varying the number
/// of values indexed under this keyword.
pub fn bench_memory_search_multiple_bindings<
    Memory: Clone + Send + Sync + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
>(
    memory_name: &str,
    n: usize,
    m: impl AsyncFn() -> Memory,
    c: &mut Criterion,
    rng: &mut impl CryptoRngCore,
) {
    // Redis memory backend requires a tokio runtime, and all operations to
    // happen in the same runtime, otherwise the connection returns a broken
    // pipe error.
    let rt = Runtime::new().unwrap();

    let findex = Findex::new(
        MemoryEncryptionLayer::new(&Secret::random(rng), rt.block_on(m())),
        dummy_encode::<WORD_LENGTH, _>,
        dummy_decode,
    );

    let index = build_benchmarking_bindings_index(n, rng);

    index
        .clone()
        .into_iter()
        .for_each(|(kw, vs)| rt.block_on(findex.insert(kw, vs)).unwrap());

    let mut group = c.benchmark_group(format!("multiple-binding search ({})", memory_name));
    for (kw, vals) in index.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(vals.len()), &(), |b, ()| {
            b.iter(|| rt.block_on(findex.search(kw)).expect("search failed"));
        });
    }
}

/// Bench the time required to a group of parallel processes to search for a
/// keyword, varying the number of processes.
pub fn bench_memory_search_multiple_keywords<
    Memory: 'static
        + Clone
        + Send
        + Sync
        + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
>(
    memory_name: &str,
    n: usize,
    m: impl AsyncFn() -> Memory,
    c: &mut Criterion,
    rng: &mut impl CryptoRngCore,
) {
    // Redis memory backend requires a tokio runtime, and all operations to
    // happen in the same runtime, otherwise the connection returns a broken
    // pipe error.
    let rt = Runtime::new().unwrap();

    let findex = Arc::new(Findex::new(
        MemoryEncryptionLayer::new(&Secret::random(rng), rt.block_on(m())),
        dummy_encode::<WORD_LENGTH, _>,
        dummy_decode,
    ));

    let index = build_benchmarking_keywords_index(rng);

    index
        .clone()
        .into_iter()
        .for_each(|(kw, vs)| rt.block_on(findex.insert(kw, vs)).unwrap());

    let mut group = c.benchmark_group(format!("multiple-keyword search ({memory_name})"));
    for i in make_scale(1, MAX_VAL, n) {
        let n = i.ceil() as usize;
        group.bench_function(BenchmarkId::from_parameter(n), |b| {
            b.iter_batched(
                || {
                    (
                        index
                            .iter()
                            .take(n)
                            .map(|(kw, _)| kw)
                            .cloned()
                            .collect::<Vec<_>>(),
                        findex.clone(),
                    )
                },
                |(kws, findex)| {
                    rt.block_on(async {
                        let mut handles = Vec::with_capacity(n);
                        for kw in kws {
                            let findex = findex.clone();
                            handles.push(tokio::spawn(async move { findex.search(&kw).await }))
                        }
                        for res in join_all(handles).await {
                            res.unwrap().unwrap();
                        }
                    })
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
}

/// Bench the time required to insert new values under a given label, varying
/// the number of inserted values.
pub fn bench_memory_insert_multiple_bindings<
    E: Debug,
    Memory: 'static
        + Clone
        + Send
        + Sync
        + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
>(
    memory_name: &str,
    n: usize,
    m: impl AsyncFn() -> Memory,
    c: &mut Criterion,
    clear: impl AsyncFn(&Memory) -> Result<(), E>,
    rng: &mut impl CryptoRngCore,
) {
    // Redis memory backend requires a tokio runtime, and all operations to
    // happen in the same runtime, otherwise the connection returns a broken
    // pipe error.
    let rt = Runtime::new().unwrap();

    let mut m = rt.block_on(m());

    let findex = Arc::new(Findex::new(
        MemoryEncryptionLayer::new(&Secret::random(rng), m.clone()),
        dummy_encode::<WORD_LENGTH, _>,
        dummy_decode,
    ));

    let index = build_benchmarking_bindings_index(n, rng);

    index
        .clone()
        .into_iter()
        .for_each(|(kw, vs)| rt.block_on(findex.insert(kw, vs)).unwrap());

    let mut group = c.benchmark_group(format!("multiple-binding insert ({memory_name})"));
    for (kw, vs) in index.into_iter() {
        group.bench_function(BenchmarkId::from_parameter(vs.len()), |b| {
            b.iter_batched(
                || {
                    rt.block_on(clear(&mut m)).unwrap();
                    (kw, vs.clone())
                },
                |(kw, vs)| rt.block_on(findex.insert(kw, vs)).expect("search failed"),
                criterion::BatchSize::SmallInput,
            );
        });
    }
}

/// Bench the time required for a group of process to perform insertions, both
/// in parallel (targeting different keywords) and in concurrence (targeting the
/// same keyword), varying the number of processes.
pub fn bench_memory_contention<
    E: Debug,
    Memory: 'static
        + Clone
        + Send
        + Sync
        + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
>(
    memory_name: &str,
    n: usize,
    m: impl AsyncFn() -> Memory,
    c: &mut Criterion,
    clear: impl AsyncFn(&Memory) -> Result<(), E>,
    rng: &mut impl CryptoRngCore,
) {
    const N_CLIENTS: usize = 10;

    // Redis memory backend requires a tokio runtime, and all operations to
    // happen in the same runtime, otherwise the connection returns a broken
    // pipe error.
    let rt = Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .unwrap();

    let m = rt.block_on(m());

    let findex = Arc::new(Findex::new(
        MemoryEncryptionLayer::new(&Secret::random(rng), m.clone()),
        dummy_encode::<WORD_LENGTH, _>,
        dummy_decode,
    ));

    // Reference: parallel clients.
    {
        let mut group = c.benchmark_group(format!("parallel clients ({memory_name}"));
        for x in make_scale(1, N_CLIENTS, n.min(N_CLIENTS)) {
            let n_clients = x.ceil() as usize;
            let bindings = (0..n_clients)
                .map(|_| {
                    let kw = rng.next_u64().to_be_bytes(); // All clients use a different keyword.
                    let vs = HashSet::<[u8; 8]>::from_iter([rng.next_u64().to_be_bytes()]);
                    (kw, vs)
                })
                .collect::<Vec<_>>();

            group.bench_function(BenchmarkId::from_parameter(n_clients), |b| {
                b.iter_batched(
                    || {
                        rt.block_on(clear(&m)).unwrap();
                        (0..n_clients).map(|_| findex.clone()).zip(bindings.clone())
                    },
                    |iterator| {
                        rt.block_on(async {
                            join_all(iterator.map(|(findex, (kw, vs))| {
                                tokio::spawn(async move { findex.insert(kw, vs).await })
                            }))
                            .await
                        })
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    }

    // Concurrent clients.
    {
        // All clients use the same keyword.
        let kw = rng.next_u64().to_be_bytes();
        let mut group = c.benchmark_group(format!("concurrent clients ({memory_name}"));
        for x in make_scale(1, N_CLIENTS, n.min(N_CLIENTS)) {
            let n_clients = x.ceil() as usize;
            let bindings = (0..n_clients)
                .map(|_| {
                    let vs = HashSet::<[u8; 8]>::from_iter([rng.next_u64().to_be_bytes()]);
                    (kw, vs)
                })
                .collect::<Vec<_>>();

            group.bench_function(BenchmarkId::from_parameter(n_clients), |b| {
                b.iter_batched(
                    || {
                        rt.block_on(clear(&m)).unwrap();
                        (
                            Vec::with_capacity(n_clients),
                            (0..n_clients).map(|_| findex.clone()).zip(bindings.clone()),
                        )
                    },
                    |(mut handles, iterator)| {
                        rt.block_on(async {
                            for (findex, (kw, vs)) in iterator {
                                let h = tokio::spawn(async move { findex.insert(kw, vs).await });
                                handles.push(h);
                            }
                            join_all(handles).await
                        })
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    }
}

/// Bench the time required to process both a read and an insertion, varying the
/// number of concurrent processes performing insertions (on the same keyword).
pub fn bench_memory_one_to_many<
    E: Debug,
    Memory: 'static
        + Clone
        + Send
        + Sync
        + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
>(
    memory_name: &str,
    n: usize,
    m: impl AsyncFn() -> Memory,
    c: &mut Criterion,
    clear: impl AsyncFn(&Memory) -> Result<(), E>,
    rng: &mut impl CryptoRngCore,
) {
    let max_val = 100;
    // Redis memory backend requires a tokio runtime, and all operations to
    // happen in the same runtime, otherwise the connection returns a broken
    // pipe error.
    let rt = Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .unwrap();

    let m = rt.block_on(m());

    let findex = Arc::new(Findex::new(
        MemoryEncryptionLayer::new(&Secret::random(rng), m.clone()),
        dummy_encode::<WORD_LENGTH, _>,
        dummy_decode,
    ));

    {
        let mut group = c.benchmark_group(format!("one search to many insertions ({memory_name}"));
        for x in make_scale(1, max_val, n) {
            let n_clients = x.ceil() as usize;

            // All clients use the same keyword and values.
            let kw = rng.next_u64().to_be_bytes();
            let vs = HashSet::<[u8; 8]>::from_iter([rng.next_u64().to_be_bytes()]);

            group.bench_function(BenchmarkId::from_parameter(n_clients), |b| {
                b.iter_batched(
                    || {
                        rt.block_on(clear(&m)).unwrap();
                        (
                            Vec::with_capacity(n_clients),
                            (0..n_clients).map(|_| (findex.clone(), vs.clone())),
                        )
                    },
                    |(mut handles, iterator)| {
                        rt.block_on(async {
                            for (findex, vs) in iterator {
                                handles.push(tokio::spawn(async move {
                                    loop {
                                        findex.insert(kw, vs.clone()).await.unwrap();
                                    }
                                }));
                            }

                            let findex = findex.clone();
                            tokio::spawn(async move {
                                let kw = kw;
                                findex.search(&kw).await.unwrap();
                            })
                            .await
                            .unwrap();

                            for h in handles {
                                h.abort();
                            }
                        })
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    }

    {
        let mut group =
            c.benchmark_group(format!("one insertion to many insertions ({memory_name})"));
        for x in make_scale(1, max_val, n) {
            let n_clients = x.ceil() as usize;

            // All clients use the same keyword and values.
            let kw = rng.next_u64().to_be_bytes();
            let vs = HashSet::<[u8; 8]>::from_iter([rng.next_u64().to_be_bytes()]);

            group.bench_function(BenchmarkId::from_parameter(n_clients), |b| {
                b.iter_batched(
                    || {
                        rt.block_on(clear(&m)).unwrap();
                    },
                    |_| {
                        rt.block_on(async {
                            let mut handles = Vec::new();
                            for _ in 0..n_clients {
                                let findex = findex.clone();
                                let vs = vs.clone();
                                handles.push(tokio::spawn(async move {
                                    loop {
                                        findex.insert(kw, vs.clone()).await.unwrap();
                                    }
                                }));
                            }

                            let findex = findex.clone();
                            let vs = vs.clone();
                            tokio::spawn(async move {
                                let kw = kw;
                                findex.insert(&kw, vs).await.unwrap();
                            })
                            .await
                            .unwrap();

                            for h in handles {
                                h.abort();
                            }
                        })
                    },
                    criterion::BatchSize::SmallInput,
                );
            });
        }
    }
}
