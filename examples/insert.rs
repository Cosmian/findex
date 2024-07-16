use std::collections::HashSet;

use cosmian_crypto_core::{
    reexport::rand_core::{CryptoRngCore, SeedableRng},
    CsRng, Secret,
};
use findex::{dummy_decode, dummy_encode, Findex, IndexADT, InMemory, Value};
use futures::executor::block_on;

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
    let mut rng = CsRng::from_entropy();
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
