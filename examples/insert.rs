use std::collections::HashSet;

#[cfg(feature = "test-utils")]
use cosmian_findex::{dummy_decode, dummy_encode};
use cosmian_findex::{Findex, InMemory, IndexADT, Secret, Value};
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
        seed,
        InMemory::default(),
        dummy_encode::<16, _>,
        dummy_decode,
    );
    let kw = index[1].0;
    block_on(findex.insert(index.into_iter())).expect("insert failed");
    block_on(findex.search(vec![kw; 10000].into_iter())).expect("search failed");
}
