#![allow(non_snake_case)]

use std::cmp::Ordering;

use crate::{LocalitySensitiveHash, vectors::F32Vector};
use rand::Rng;
use std::hash::{Hash, Hasher};

#[derive(Debug, Clone, PartialEq)]
pub struct Parameters {
    pub K: usize,
    pub L: usize,
}

#[derive(Debug, Clone, PartialOrd)]
pub struct Probe(usize, usize);

impl Eq for Probe {}

impl PartialEq for Probe {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}

impl Hash for Probe {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
        self.1.hash(state);
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FalconLsh<const D: usize>(Vec<Vec<(F32Vector<D>, F32Vector<D>)>>);

impl<const D: usize> LocalitySensitiveHash for FalconLsh<D> {
    type Parameters = Parameters;

    type Input = F32Vector<D>;

    type Probe = Probe;

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
    ) -> Result<Vec<impl IntoIterator<Item = (Self::Probe, Self::Score)>>, String> {
        let Some(nprob) = nprob else {
            return Err("nprob must be given".to_owned());
        };
        Ok(self
            .0
            .iter()
            .map(|families| {
                let (mut ip_family1, mut ip_family2): (Vec<_>, Vec<_>) = families
                    .iter()
                    .enumerate()
                    .map(|(i, (v1, v2))| {
                        let ip1 = point.inner_product(v1);
                        let ip2 = point.inner_product(v2);
                        ((i, ip1), (i, ip2))
                    })
                    .unzip();

                ip_family1.sort_by(|ip1, ip2| {
                    if ip1.1 > ip2.1 {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                });

                ip_family2.sort_by(|ip1, ip2| {
                    if ip1.1 > ip2.1 {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                });

                ip_family1
                    .into_iter()
                    .take(nprob)
                    .map({
                        |ip1| {
                            ip_family2.iter().take(nprob).map({
                                let ip1 = ip1.clone();
                                move |&ip2| (Probe(ip1.0, ip2.0), ip1.1.min(ip2.1))
                            })
                        }
                    })
                    .flatten()
                    .collect::<Vec<_>>()
                    .into_iter()
            })
            .collect::<Vec<_>>())
    }
}
