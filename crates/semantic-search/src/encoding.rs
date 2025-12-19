#[cfg(feature = "python")]
mod string;

#[cfg(feature = "python")]
pub use string::StringEncoder;

use cosmian_findex::Op;
use std::{collections::HashSet, hash::Hash};

// Encoding are better described using a trait. However, this is not how they
// are described in Findex. To avoid a breaking change, this new traits lives
// here for now.
pub trait Encoding {
    type Value: Hash + Eq;
    type Chunk;
    type Error: std::error::Error;

    fn encode(op: Op, values: HashSet<Self::Value>) -> Result<Vec<Self::Chunk>, Self::Error>;
    fn decode(chunks: Vec<Self::Chunk>) -> Result<HashSet<Self::Value>, Self::Error>;
}

#[cfg(test)]
use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
#[cfg(test)]
use std::fmt::Debug;

#[cfg(test)]
pub fn test_encoding<E: Encoding>(seed: [u8; 32], gen_val: fn(&mut CsRng) -> E::Value)
where
    E::Value: Clone + Debug,
{
    const N: usize = 1_000;
    let mut rng = CsRng::from_seed(seed);
    let values = (0..N).map(|_| gen_val(&mut rng)).collect::<HashSet<_>>();
    let _values = E::decode(E::encode(Op::Insert, values.clone()).unwrap()).unwrap();
    assert_eq!(values, _values);
}
