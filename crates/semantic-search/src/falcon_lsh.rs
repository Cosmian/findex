#![allow(non_snake_case)]

use std::cmp::{self, Ordering};

use crate::{LocalitySensitiveHash, vectors::F32Vector};
use rand::Rng;

#[derive(Debug, Clone, PartialEq)]
pub struct Parameters {
    pub K: usize,
    pub L: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FalconLsh<const D: usize>(Vec<Vec<(F32Vector<D>, F32Vector<D>)>>);

impl<const D: usize> LocalitySensitiveHash for FalconLsh<D> {
    type Parameters = Parameters;

    type Input = F32Vector<D>;

    type Probe = (f32, f32);

    type Score = f32;

    fn init(params: &Self::Parameters, rng: &mut impl Rng) -> Self {
        Self(
            (0..params.L)
                .map(|_| {
                    (0..params.K)
                        .map(|_| {
                            (
                                F32Vector::random_unit_vector(rng),
                                F32Vector::random_unit_vector(rng),
                            )
                        })
                        .collect()
                })
                .collect(),
        )
    }

    fn hash(
        &self,
        point: &Self::Input,
        nprob: Option<usize>,
    ) -> Vec<impl IntoIterator<Item = (Self::Probe, Self::Score)>> {
        let nprob = nprob.unwrap();
        self.0
            .iter()
            .map(|families| {
                let (mut ip_family1, mut ip_family2): (Vec<_>, Vec<_>) = families
                    .iter()
                    .map(|(v1, v2)| {
                        let ip1 = point.inner_product(v1);
                        let ip2 = point.inner_product(v2);
                        (ip1, ip2)
                    })
                    .unzip();
                ip_family1.sort_by(|ip1, ip2| {
                    if ip1 > ip2 {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                });
                ip_family2.sort_by(|ip1, ip2| {
                    if ip1 > ip2 {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                });
                ip_family1.into_iter().take(nprob).flat_map(|ip1| {
                    ip_family2
                        .iter()
                        .take(nprob)
                        .map(|&ip2| ((ip1, ip2), ip1.min(ip2)))
                })
            })
            .collect::<Vec<_>>()
        //TODO: filter the probes according to the iProbes parameter
    }
}
