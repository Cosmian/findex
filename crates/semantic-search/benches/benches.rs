use cosmian_crypto_core::{CsRng, Secret, reexport::rand_core::SeedableRng};
use cosmian_findex::{Findex, MemoryEncryptionLayer, Op};
use cosmian_semantic_search::{
    cleartext_index::CleartextIndex, Error, F32Vector, F64Vector, LocalitySensitiveHash, LshVectorDB, SimpleLsh, SimpleLshParameters, VectorDB
};
use cosmian_sse_memories::{
    ADDRESS_LENGTH, Address, InMemory, MemoryADT, PostgresMemory, RedisMemory,
};
use criterion::{Criterion, criterion_group, criterion_main};
use rand::rngs::ThreadRng;
use std::collections::HashSet;
use tokio::runtime::Builder;

fn bench_ip(c: &mut Criterion) {
    const D: usize = 384;

    let mut rng = ThreadRng::default();
    let mut group = c.benchmark_group("Inner Product (D = {D})");
    {
        let v1 = F32Vector::<D>::random_unit_vector(&mut rng);
        let v2 = F32Vector::<D>::random_unit_vector(&mut rng);
        group.bench_function(format!("f32"), |b| {
            b.iter(|| v1.inner_product(&v2));
        });
    }
    {
        let v1 = F64Vector::<D>::random_unit_vector(&mut rng);
        let v2 = F64Vector::<D>::random_unit_vector(&mut rng);
        group.bench_function(format!("f64"), |b| {
            b.iter(|| v1.inner_product(&v2));
        });
    }
}

fn bench_simple_lsh(c: &mut Criterion) {
    const D: usize = 384;
    const K: usize = 20;
    const L: usize = 20;

    let mut rng = ThreadRng::default();
    let mut group = c.benchmark_group("SimpleLsh");
    {
        group.bench_function("init".to_string(), |b| {
            b.iter(|| SimpleLsh::<D>::init(&SimpleLshParameters { K, L }, &mut rng));
        });
    }
    {
        let lsh = SimpleLsh::init(&SimpleLshParameters { K, L }, &mut rng);
        let v = F32Vector::<D>::random_unit_vector(&mut rng);
        group.bench_function("hash".to_string(), |b| {
            b.iter(|| lsh.hash(&v).into_iter().collect::<Vec<_>>());
        });
    }
}

fn bench_cleartext_vector_db(c: &mut Criterion) {
    const D: usize = 384;
    const K: usize = 20;
    const L: usize = 20;
    const N: usize = 10_000;

    let mut rng = ThreadRng::default();

    let lsh = SimpleLsh::<D>::init(&SimpleLshParameters { K, L }, &mut rng);
    let idx = CleartextIndex::default();
    let vdb = LshVectorDB::init((lsh, idx)).unwrap();

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    let _ = rt.enter();

    for _ in 0..N {
        rt.block_on(vdb.insert(F32Vector::<D>::random_unit_vector(&mut rng)))
            .unwrap();
    }

    let q_in = F32Vector::<D>::random_unit_vector(&mut rng);
    let q_ex = F32Vector::<D>::random_unit_vector(&mut rng);

    let mut group = c.benchmark_group("Cleartext VectorDB");
    {
        group.bench_function(format!("insert (pop #{N})"), |b| {
            b.iter(|| rt.block_on(vdb.query(10, &q_in)).unwrap());
        });
    }
    {
        group.bench_function(format!("search (pop #{N}, match)"), |b| {
            b.iter(|| rt.block_on(vdb.query(10, &q_in)).unwrap());
        });
    }
    {
        group.bench_function(format!("search (pop #{N}, no match)"), |b| {
            b.iter(|| rt.block_on(vdb.query(10, &q_ex)).unwrap());
        });
    }
}

const D: usize = 384;
const F32_LENGTH: usize = 4;
const WORD_LENGTH: usize = 1 + F32_LENGTH * D;

fn bench_with_memory<Memory>(
    c: &mut Criterion,
    rt: &tokio::runtime::Runtime,
    mem: Memory,
    msg: &str,
) where
    Memory: 'static
        + Send
        + Sync
        + Clone
        + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
{
    const K: usize = 20;
    const L: usize = 20;
    const N: usize = 10_000;

    let mut rng = ThreadRng::default();

    let lsh = SimpleLsh::<D>::init(&SimpleLshParameters { K, L }, &mut rng);

    let idx = {
        fn vector_encode<const D: usize>(
            op: Op,
            values: HashSet<F32Vector<D>>,
        ) -> Result<Vec<[u8; WORD_LENGTH]>, Error> {
            Ok(values
                .into_iter()
                .map(|v| {
                    let mut res = [0; WORD_LENGTH];
                    res[0] = if op == Op::Insert { 0 } else { 1 };
                    for (i, e) in v.into_iter().enumerate() {
                        res[1 + F32_LENGTH * i..1 + F32_LENGTH * (i + 1)]
                            .copy_from_slice(&e.to_be_bytes());
                    }
                    res
                })
                .collect())
        }

        fn vector_decode<const D: usize>(
            ws: Vec<[u8; WORD_LENGTH]>,
        ) -> Result<HashSet<F32Vector<D>>, Error> {
            ws.into_iter()
                .map(|w| {
                    F32Vector::<D>::init(|i| {
                        <[u8; F32_LENGTH]>::try_from(
                            &w[1 + F32_LENGTH * i..1 + F32_LENGTH * (i + 1)],
                        )
                        .map_err(|e| Error(e.to_string()))
                        .map(f32::from_be_bytes)
                    })
                })
                .collect()
        }

        let key = Secret::<{ cosmian_findex::KEY_LENGTH }>::random(&mut CsRng::from_entropy());

        Findex::<WORD_LENGTH, F32Vector<D>, _, _>::new(
            MemoryEncryptionLayer::new(&key, mem),
            vector_encode,
            vector_decode,
        )
    };

    let vdb = LshVectorDB::init((lsh.clone(), idx)).unwrap();

    for _ in 0..N {
        rt.block_on(vdb.insert(F32Vector::<D>::random_unit_vector(&mut rng)))
            .unwrap();
    }

    let q_in = F32Vector::<D>::random_unit_vector(&mut rng);
    let q_ex = F32Vector::<D>::random_unit_vector(&mut rng);

    let mut group = c.benchmark_group(format!("Encrypted VectorDB over {msg}"));
    {
        group.bench_function(format!("search (pop. #{N}, match)"), |b| {
            b.iter(|| rt.block_on(vdb.query(10, &q_in)).unwrap());
        });
    }
    {
        group.bench_function(format!("search (pop. #{N}, no match)"), |b| {
            b.iter(|| rt.block_on(vdb.query(10, &q_ex)).unwrap());
        });
    }
    {
        group.bench_function(format!("Insert (base pop. #{N})"), |b| {
            b.iter_batched(
                || q_ex.clone(),
                |q_ex| rt.block_on(vdb.insert(q_ex)).unwrap(),
                criterion::BatchSize::SmallInput,
            );
        });
    }
}

fn bench_encrypted_vector_db_in_memory(c: &mut Criterion) {
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    let _ = rt.enter();
    let mem = InMemory::<Address<{ ADDRESS_LENGTH }>, [u8; WORD_LENGTH]>::default();
    bench_with_memory(c, &rt, mem, "in-memory");
}

fn bench_encrypted_vector_db_redis(c: &mut Criterion) {
    fn get_redis_url() -> String {
        std::env::var("REDIS_HOST").map_or_else(
            |_| "redis://localhost:6379".to_owned(),
            |var_env| format!("redis://{var_env}:6379"),
        )
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    // let _ = rt.enter();
    let mem = rt
        .block_on(RedisMemory::new_with_url(&get_redis_url()))
        .unwrap();

    bench_with_memory(c, &rt, mem, "Redis");
}

fn bench_encrypted_vector_db_postgre(c: &mut Criterion) {
    const DB_URL: &str = "postgres://cosmian:cosmian@localhost/cosmian";

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    let _ = rt.enter();
    let mem = rt
        .block_on(PostgresMemory::new(
            DB_URL.to_string(),
            "pg_semantic_benches".to_string(),
        ))
        .unwrap();

    rt.block_on(mem.initialize()).unwrap();

    bench_with_memory(c, &rt, mem, "PostgreSQL");
}

criterion_group!(
    benches,
    bench_ip,
    bench_simple_lsh,
    bench_cleartext_vector_db,
    bench_encrypted_vector_db_in_memory,
    bench_encrypted_vector_db_redis,
    bench_encrypted_vector_db_postgre,
);
criterion_main!(benches);
