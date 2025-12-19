use cosmian_crypto_core::{CsRng, Secret, reexport::rand_core::SeedableRng};
use cosmian_findex::{Findex, MemoryEncryptionLayer, Op};
use cosmian_semantic_search::{
    Error, F32Vector, LocalitySensitiveHash, LshVectorDB, SimpleLsh, SimpleLshParameters, VectorDB,
    cleartext_index::CleartextIndex,
};
use cosmian_sse_memories::{ADDRESS_LENGTH, Address, InMemory};
use futures::executor::block_on;
use std::collections::HashSet;

#[test]
fn test_cleartext_vector_db() {
    use rand::rngs::ThreadRng;

    const D: usize = 384;
    const N: usize = 1_000;
    const K: usize = 20;
    const L: usize = 20;

    let mut rng = ThreadRng::default();
    let lsh = SimpleLsh::init(&SimpleLshParameters { K, L }, &mut rng);
    let index = CleartextIndex::default();
    let vdb = LshVectorDB::init((lsh, index)).unwrap();

    let vs = (0..N)
        .map(|_| F32Vector::<D>::random_unit_vector(&mut rng))
        .collect::<Vec<_>>();

    for vi in vs.clone() {
        block_on(vdb.insert(vi)).unwrap();
    }

    for vi in &vs {
        let candidates = block_on(vdb.query(10, vi)).unwrap();
        assert!(!candidates.is_empty());
        assert_eq!(vi, &candidates[0].0);
    }
}

#[test]
fn test_findex_vector_db() {
    use rand::rngs::ThreadRng;

    const D: usize = 384;
    const N: usize = 1_000;
    const K: usize = 32;
    const L: usize = 32;

    let findex = {
        const F32_LENGTH: usize = 4;
        const WORD_LENGTH: usize = 1 + F32_LENGTH * 384;

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
        let mem = InMemory::<Address<{ ADDRESS_LENGTH }>, [u8; WORD_LENGTH]>::with_capacity(L * N);

        Findex::<WORD_LENGTH, F32Vector<D>, _, _>::new(
            MemoryEncryptionLayer::new(&key, mem),
            vector_encode,
            vector_decode,
        )
    };

    let mut rng = ThreadRng::default();
    let lsh = SimpleLsh::init(&SimpleLshParameters { K, L }, &mut rng);
    let vdb = LshVectorDB::init((lsh, findex)).unwrap();

    let vs = (0..N)
        .map(|_| F32Vector::<D>::random_unit_vector(&mut rng))
        .collect::<Vec<_>>();

    for vi in vs.clone() {
        block_on(vdb.insert(vi)).unwrap();
    }

    for vi in &vs {
        let candidates = block_on(vdb.query(10, vi)).unwrap();
        assert!(!candidates.is_empty());
        assert_eq!(vi, &candidates[0].0);
    }
}
