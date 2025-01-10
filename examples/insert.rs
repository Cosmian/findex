use std::collections::HashSet;

use cosmian_findex::{Findex, InMemory, IndexADT, Secret, Value, dummy_decode, dummy_encode};
use futures::executor::block_on;
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRngCore, SeedableRng};

fn build_benchmarking_index(rng: &mut impl CryptoRngCore) -> Vec<([u8; 8], HashSet<Value>)> {
    (0..6)
        .map(|i| {
            let kw = rng.next_u64().to_be_bytes();
            let vals = (0..10_i64.pow(i) as usize)
                .map(|_| Value::from(rng.next_u64() as usize))
                .collect::<HashSet<_>>();
            (kw, vals)
        })
        .collect()
}

fn main() {
    let mut rng = ChaChaRng::from_entropy();
    let index = build_benchmarking_index(&mut rng);
    let seed = Secret::random(&mut rng);
    let findex = Findex::new(
        &seed,
        InMemory::default(),
        dummy_encode::<16, _>,
        dummy_decode,
    );

    let kw = index[1].0;
    let vs = index[1].1.iter().cloned().collect::<Vec<_>>();

    index
        .into_iter()
        .for_each(|(kw, vs)| block_on(findex.insert(kw, vs)).expect("insert failed"));

    let res = vec![kw; 1_000]
        .iter()
        .map(|kw| {
            block_on(findex.search(kw))
                .expect("search failed")
                .into_iter()
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    assert_eq!(res, vec![vs; 1_000])
}
