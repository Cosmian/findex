use cosmian_crypto_core::{CryptoCoreError, bytes_ser_de::Serializable};
use rand::Rng;
use rand_distr::StandardNormal;
use std::{array::TryFromSliceError, cmp::Ordering, hash::Hash};

const UNROLLING_LEVEL: usize = 4;

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
        let mut acc = 0.;
        let q = D >> UNROLLING_LEVEL;
        for i in 0..q {
            let pos = i << UNROLLING_LEVEL;
            let x15 = self.0[pos + 15];
            let x14 = self.0[pos + 14];
            let x13 = self.0[pos + 13];
            let x12 = self.0[pos + 12];
            let x11 = self.0[pos + 11];
            let x10 = self.0[pos + 10];
            let x9 = self.0[pos + 9];
            let x8 = self.0[pos + 8];
            let x7 = self.0[pos + 7];
            let x6 = self.0[pos + 6];
            let x5 = self.0[pos + 5];
            let x4 = self.0[pos + 4];
            let x3 = self.0[pos + 3];
            let x2 = self.0[pos + 2];
            let x1 = self.0[pos + 1];
            let x0 = self.0[pos];
            let y15 = other.0[pos + 15];
            let y14 = other.0[pos + 14];
            let y13 = other.0[pos + 13];
            let y12 = other.0[pos + 12];
            let y11 = other.0[pos + 11];
            let y10 = other.0[pos + 10];
            let y9 = other.0[pos + 9];
            let y8 = other.0[pos + 8];
            let y7 = other.0[pos + 7];
            let y6 = other.0[pos + 6];
            let y5 = other.0[pos + 5];
            let y4 = other.0[pos + 4];
            let y3 = other.0[pos + 3];
            let y2 = other.0[pos + 2];
            let y1 = other.0[pos + 1];
            let y0 = other.0[pos];
            // Use tree-shaped circuit to break linearity and benefit from
            // super-scalar processor capabilities.
            acc += (((x0 * y0 + x1 * y1) + (x2 * y2 + x3 * y3))
                + ((x4 * y4 + x5 * y5) + (x6 * y6 + x7 * y7)))
                + (((x8 * y8 + x9 * y9) + (x10 * y10 + x11 * y11))
                    + ((x12 * y12 + x13 * y13) + (x14 * y14 + x15 * y15)));
        }

        for pos in (q << UNROLLING_LEVEL)..D {
            acc += self.0[pos] * other.0[pos];
        }

        acc
    }

    pub fn mips_with<T>(
        &self,
        f: fn(&T) -> &Self,
        k: usize,
        vs: impl IntoIterator<Item = T>,
    ) -> Vec<(T, f32)> {
        let mut tmp = vs
            .into_iter()
            .map(|v| {
                let ip = self.inner_product(f(&v));
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

impl<const D: usize> TryFrom<&[f32]> for F32Vector<D> {
    type Error = TryFromSliceError;

    fn try_from(value: &[f32]) -> Result<Self, Self::Error> {
        let value = <[f32; D]>::try_from(value)?;
        Ok(Self(value))
    }
}

impl<const D: usize> Serializable for F32Vector<D> {
    type Error = CryptoCoreError;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer) -> Result<usize, Self::Error> {
        self.0.write(ser)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        de.read().map(Self)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct F64Vector<const D: usize>([f64; D]);

impl<const D: usize> Eq for F64Vector<D> {}

impl<const D: usize> Hash for F64Vector<D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.iter().for_each(|e| state.write(&e.to_be_bytes()))
    }
}

impl<const D: usize> F64Vector<D> {
    pub fn init<Error: std::error::Error>(
        f: impl Fn(usize) -> Result<f64, Error>,
    ) -> Result<Self, Error> {
        let mut elements = [0f64; D];
        for (i, e) in elements.iter_mut().enumerate() {
            *e = f(i)?;
        }
        Ok(Self(elements))
    }

    fn norm(&self) -> f64 {
        self.0.iter().map(|x| x * x).sum::<f64>().sqrt()
    }

    pub fn random_unit_vector(rng: &mut impl Rng) -> Self {
        let mut v = Self([0f64; D]);
        v.0.iter_mut()
            .for_each(|vi| *vi = rng.sample(StandardNormal));
        let norm = v.norm();
        v.0.iter_mut().for_each(|vi| *vi /= norm);
        v
    }

    /// Returns the inner product of this vector with given one.
    pub fn inner_product(&self, other: &Self) -> f64 {
        let mut acc = 0f64;
        let q = D >> 4;
        for i in 0..q {
            let pos = i << 4;
            let x15 = self.0[pos + 15];
            let x14 = self.0[pos + 14];
            let x13 = self.0[pos + 13];
            let x12 = self.0[pos + 12];
            let x11 = self.0[pos + 11];
            let x10 = self.0[pos + 10];
            let x9 = self.0[pos + 9];
            let x8 = self.0[pos + 8];
            let x7 = self.0[pos + 7];
            let x6 = self.0[pos + 6];
            let x5 = self.0[pos + 5];
            let x4 = self.0[pos + 4];
            let x3 = self.0[pos + 3];
            let x2 = self.0[pos + 2];
            let x1 = self.0[pos + 1];
            let x0 = self.0[pos];
            let y15 = other.0[pos + 15];
            let y14 = other.0[pos + 14];
            let y13 = other.0[pos + 13];
            let y12 = other.0[pos + 12];
            let y11 = other.0[pos + 11];
            let y10 = other.0[pos + 10];
            let y9 = other.0[pos + 9];
            let y8 = other.0[pos + 8];
            let y7 = other.0[pos + 7];
            let y6 = other.0[pos + 6];
            let y5 = other.0[pos + 5];
            let y4 = other.0[pos + 4];
            let y3 = other.0[pos + 3];
            let y2 = other.0[pos + 2];
            let y1 = other.0[pos + 1];
            let y0 = other.0[pos];
            // Use tree-shaped circuit to break linearity and benefit from
            // super-scalar processor capabilities.
            acc += (((x0 * y0 + x1 * y1) + (x2 * y2 + x3 * y3))
                + ((x4 * y4 + x5 * y5) + (x6 * y6 + x7 * y7)))
                + (((x8 * y8 + x9 * y9) + (x10 * y10 + x11 * y11))
                    + ((x12 * y12 + x13 * y13) + (x14 * y14 + x15 * y15)));
        }

        for pos in q << 4..D {
            acc += self.0[pos] * other.0[pos];
        }

        acc
    }

    pub fn mips(&self, k: usize, vs: impl IntoIterator<Item = Self>) -> Vec<(Self, f64)> {
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

impl<const D: usize> IntoIterator for F64Vector<D> {
    type Item = f64;

    type IntoIter = std::array::IntoIter<f64, D>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<const D: usize> TryFrom<&[f64]> for F64Vector<D> {
    type Error = TryFromSliceError;

    fn try_from(value: &[f64]) -> Result<Self, Self::Error> {
        let value = <[f64; D]>::try_from(value)?;
        Ok(Self(value))
    }
}
