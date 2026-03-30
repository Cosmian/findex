use core::hash::Hash;
use std::collections::HashSet;

use cosmian_crypto_core::{
    CsRng, Secret, bytes_ser_de::Serializable, reexport::rand_core::SeedableRng,
};
use cosmian_findex::{Findex, MemoryEncryptionLayer, Op, generic_decode, generic_encode};
use cosmian_semantic_search::{
    Error, F32Vector, LocalitySensitiveHash, SimpleLsh, SimpleLshParameters, VDBParameters, Vdb,
    VectorDB, cleartext_index,
};
use cosmian_sse_memories::{ADDRESS_LENGTH, Address, InMemory};
use futures::executor::block_on;

#[test]
fn test_cleartext_vector_db() {
    use rand::rngs::ThreadRng;

    const D: usize = 384;
    const N: usize = 1_000;
    const K: usize = 20;
    const L: usize = 20;

    let mut rng = ThreadRng::default();
    let lsh = SimpleLsh::<D>::init(&SimpleLshParameters { K, L }, &mut rng);
    let index = cleartext_index::CleartextIndex::default();
    let vdb = Vdb::<D, _, _>::init(VDBParameters {
        lsh,
        index,
        iprobe: None,
        qprobe: None,
    })
    .unwrap();

    let vs = (0..N)
        .map(|_| F32Vector::<D>::random_unit_vector(&mut rng))
        .collect::<Vec<_>>();

    for vi in vs.clone() {
        block_on(vdb.insert(vi, "".to_string())).unwrap();
    }

    for vi in &vs {
        let candidates = block_on(vdb.query(10, vi)).unwrap();
        assert!(!candidates.is_empty());
        assert_eq!(vi, &candidates[0].0.0);
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

        fn vector_encode<const D: usize, T: Hash + Eq + Serializable>(
            op: Op,
            values: HashSet<(F32Vector<D>, T)>,
        ) -> Result<Vec<[u8; WORD_LENGTH]>, Error> {
            let bytes = values
                .serialize()
                .map_err(|e| Error(e.to_string()))?
                .to_vec();

            generic_encode::<WORD_LENGTH, _>(op, HashSet::from_iter([bytes]))
                .map_err(|e| Error(e.to_string()))
        }

        fn vector_decode<const D: usize, T: Hash + Eq + Serializable>(
            ws: Vec<[u8; WORD_LENGTH]>,
        ) -> Result<HashSet<(F32Vector<D>, T)>, Error> {
            let bytes = generic_decode::<WORD_LENGTH, _, Vec<u8>>(ws).map_err(|e| Error(e))?;
            bytes
                .into_iter()
                .map(|bytes| <HashSet<(F32Vector<D>, T)>>::deserialize(&bytes))
                .try_fold(HashSet::new(), |mut a, e| {
                    e.map(|set| {
                        set.into_iter().for_each(|b| {
                            a.insert(b);
                            ()
                        });
                        a
                    })
                    .map_err(|e| Error(e.to_string()))
                })
        }

        let key = Secret::<{ cosmian_findex::KEY_LENGTH }>::random(&mut CsRng::from_entropy());
        let mem = InMemory::<Address<{ ADDRESS_LENGTH }>, [u8; WORD_LENGTH]>::with_capacity(L * N);

        Findex::<WORD_LENGTH, _, _, _>::new(
            MemoryEncryptionLayer::new(&key, mem),
            vector_encode,
            vector_decode,
        )
    };

    let mut rng = ThreadRng::default();
    let lsh = SimpleLsh::init(&SimpleLshParameters { K, L }, &mut rng);
    let vdb = Vdb::<D, _, _>::init(VDBParameters {
        lsh,
        index: findex,
        iprobe: None,
        qprobe: None,
    })
    .unwrap();

    let vs = (0..N)
        .map(|_| F32Vector::<D>::random_unit_vector(&mut rng))
        .collect::<Vec<_>>();

    for vi in vs.clone() {
        block_on(vdb.insert(vi, "".to_string())).unwrap();
    }

    for vi in &vs {
        let candidates = block_on(vdb.query(10, vi)).unwrap();
        assert!(!candidates.is_empty());
        assert_eq!(vi, &candidates[0].0.0);
    }
}
