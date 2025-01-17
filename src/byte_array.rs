use std::ops::{Deref, DerefMut};

use rand_core::CryptoRngCore;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize, de::Visitor, ser::SerializeTuple};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ByteArray<const LENGTH: usize>([u8; LENGTH]);

impl<const LENGTH: usize> Default for ByteArray<LENGTH> {
    #[inline]
    fn default() -> Self {
        Self([0; LENGTH])
    }
}

impl<const LENGTH: usize> Deref for ByteArray<LENGTH> {
    type Target = [u8; LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LENGTH: usize> DerefMut for ByteArray<LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LENGTH: usize> From<[u8; LENGTH]> for ByteArray<LENGTH> {
    fn from(bytes: [u8; LENGTH]) -> Self {
        Self(bytes)
    }
}

impl<const LENGTH: usize> From<ByteArray<LENGTH>> for [u8; LENGTH] {
    fn from(bytes: ByteArray<LENGTH>) -> Self {
        bytes.0
    }
}

impl<const LENGTH: usize> ByteArray<LENGTH> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut res = Self::default();
        rng.fill_bytes(&mut *res);
        res
    }
}

#[cfg(feature = "serialization")]
impl<const LENGTH: usize> Serialize for ByteArray<LENGTH> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.iter()
            .try_fold(serializer.serialize_tuple(LENGTH)?, |mut tuple, byte| {
                tuple.serialize_element(byte)?;
                Ok(tuple)
            })?
            .end()
    }
}

#[cfg(feature = "serialization")]
impl<'de, const LENGTH: usize> Deserialize<'de> for ByteArray<LENGTH> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Default)]
        struct ByteArrayVisitor<const LENGTH: usize>;

        #[cfg(feature = "serialization")]
        impl<'de, const LENGTH: usize> Visitor<'de> for ByteArrayVisitor<LENGTH> {
            type Value = ByteArray<LENGTH>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an array of {LENGTH} bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut w = ByteArray::<LENGTH>::default();
                (0..LENGTH).try_for_each(|i| {
                    w[i] = seq
                        .next_element()?
                        .ok_or_else(|| <A::Error as serde::de::Error>::invalid_length(i, &self))?;
                    Ok::<_, A::Error>(())
                })?;
                Ok(w)
            }
        }

        deserializer.deserialize_tuple(LENGTH, ByteArrayVisitor)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "serialization")]
    #[test]
    fn test_word_serialization() {
        use super::*;
        let ws = vec![ByteArray::<129>::default(); 8];
        let bytes = bincode::serialize(&ws).unwrap();
        let res = bincode::deserialize::<Vec<_>>(&bytes).unwrap();
        assert_eq!(ws, res);
    }
}
