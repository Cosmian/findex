use rand::Rng;
use rand_distr::StandardNormal;
use std::{cmp::Ordering, hash::Hash};

#[derive(Debug, Clone, PartialEq)]
pub struct F32Vector<const D: usize>([f32; D]);

impl<const D: usize> Eq for F32Vector<D> {}

impl<const D: usize> Hash for F32Vector<D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.iter().for_each(|e| state.write(&e.to_be_bytes()))
    }
}

impl<const D: usize> F32Vector<D> {
    pub fn init<Error: std::error::Error>(
        f: impl Fn(usize) -> Result<f32, Error>,
    ) -> Result<Self, Error> {
        let mut elements = [0f32; D];
        for (i, e) in elements.iter_mut().enumerate() {
            *e = f(i)?;
        }
        Ok(Self(elements))
    }

    fn norm(&self) -> f32 {
        self.0.iter().map(|x| x * x).sum::<f32>().sqrt()
    }

    pub fn random_unit_vector(rng: &mut impl Rng) -> Self {
        let mut v = Self([0f32; D]);
        v.0.iter_mut()
            .for_each(|vi| *vi = rng.sample(StandardNormal));
        let norm = v.norm();
        v.0.iter_mut().for_each(|vi| *vi /= norm);
        v
    }

    /// Returns the inner product of this vector with given one.
    pub fn inner_product(&self, other: &Self) -> f32 {
        let mut pos = 0;
        let mut acc = 0f32;
        // Unroll loop.
        while pos + 7 < D {
            #[allow(clippy::identity_op)]
            let x0 = self.0[pos + 0];
            let x1 = self.0[pos + 1];
            let x2 = self.0[pos + 2];
            let x3 = self.0[pos + 3];
            let x4 = self.0[pos + 4];
            let x5 = self.0[pos + 5];
            let x6 = self.0[pos + 6];
            let x7 = self.0[pos + 7];
            #[allow(clippy::identity_op)]
            let y0 = other.0[pos + 0];
            let y1 = other.0[pos + 1];
            let y2 = other.0[pos + 2];
            let y3 = other.0[pos + 3];
            let y4 = other.0[pos + 4];
            let y5 = other.0[pos + 5];
            let y6 = other.0[pos + 6];
            let y7 = other.0[pos + 7];
            // Use tree-shaped circuit to break linearity and benefit from
            // super-scalar processor capabilities.
            acc += ((x0 * y0 + x1 * y1) + (x2 * y2 + x3 * y3))
                + ((x4 * y4 + x5 * y5) + (x6 * y6 + x7 * y7));
            pos += 8;
        }

        while pos < D {
            acc += self.0[pos] * other.0[pos];
            pos += 1
        }

        acc
    }

    pub fn mips(&self, k: usize, vs: impl IntoIterator<Item = Self>) -> Vec<(Self, f32)> {
        let mut tmp = vs
            .into_iter()
            .map(|v| {
                let ip = self.inner_product(&v);
                (v, ip)
            })
            .collect::<Vec<_>>();

        tmp.sort_unstable_by(|(_v1, ip1), (_v2, ip2)| {
            // Invert order as we want the highest inner-products to come first.
            if ip1 <= ip2 {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        });

        tmp.into_iter().take(k).collect()
    }
}

impl<const D: usize> IntoIterator for F32Vector<D> {
    type Item = f32;

    type IntoIter = std::array::IntoIter<f32, D>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
