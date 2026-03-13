#![allow(non_snake_case)]

use crate::{LocalitySensitiveHash, vectors::F32Vector};
use rand::Rng;

#[derive(Debug, Clone, PartialEq)]
pub struct Parameters {
    pub K: usize,
    pub L: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimpleLsh<const D: usize>(Vec<Vec<F32Vector<D>>>);

impl<const D: usize> LocalitySensitiveHash for SimpleLsh<D> {
    type Parameters = Parameters;

    type Input = F32Vector<D>;

    type Probe = u64;

    type Score = f64;

    fn init(params: &Self::Parameters, rng: &mut impl Rng) -> Self {
        assert!(
            params.L < 64,
            "The current implementation returns the list of signs as a u64. \
             There can therefore be no more than 64 such signs."
        );
        Self(
            (0..params.K)
                .map(|_| {
                    (0..params.L)
                        .map(|_| F32Vector::random_unit_vector(rng))
                        .collect()
                })
                .collect(),
        )
    }

    fn hash(
        &self,
        point: &Self::Input,
        nprobe: Option<usize>,
    ) -> Vec<impl IntoIterator<Item = (Self::Probe, Self::Score)>> {
        self.0
            .iter()
            .map(|family| {
                let (probe, score) = family.iter().map(|v| 0. < point.inner_product(v)).fold(
                    (0u64, 0u64),
                    |(n, s), b| {
                        let b = b as u64;
                        ((n << 1) + b, s + b)
                    },
                );
                std::iter::once((probe, score as f64 / family.len() as f64))
            })
            .collect()
    }
}
