use crate::{LocalitySensitiveHash, vectors::F32Vector};
use rand::Rng;

#[derive(Debug, Clone, PartialEq)]
pub struct Parameters {
    pub K: usize,
    pub L: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimpleLsh<const D: usize>(Vec<(u64, Vec<F32Vector<D>>)>);

impl<const D: usize> LocalitySensitiveHash for SimpleLsh<D> {
    type Parameters = Parameters;

    type Input = F32Vector<D>;

    type Output = (u64, u64);

    fn init(params: &Self::Parameters, rng: &mut impl Rng) -> Self {
        assert!(
            params.L < 64,
            "The current implementation returns the list of signs as a u64. \
             There can therefore be no more than 64 such signs."
        );
        Self(
            (0..params.K)
                .map(|id| {
                    (
                        id as u64,
                        (0..params.L)
                            .map(|_| F32Vector::random_unit_vector(rng))
                            .collect(),
                    )
                })
                .collect(),
        )
    }

    fn hash(&self, point: &Self::Input) -> impl IntoIterator<Item = Self::Output> {
        self.0.iter().map(|(id, family)| {
            let probe = family
                .iter()
                .map(|v| 0. < point.inner_product(v))
                .fold(0, |n, b| (n << 1) + b as u64);
            (*id, probe)
        })
    }
}
