use std::ops::{Add, Deref, DerefMut};

use rand_core::CryptoRngCore;
#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

use crate::byte_array::ByteArray;

// NOTE: a more efficient implementation of the address could be a big-int.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct Address<const LENGTH: usize>(ByteArray<LENGTH>);

impl<const LENGTH: usize> Deref for Address<LENGTH> {
    type Target = [u8; LENGTH];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LENGTH: usize> DerefMut for Address<LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LENGTH: usize> From<[u8; LENGTH]> for Address<LENGTH> {
    fn from(bytes: [u8; LENGTH]) -> Self {
        Self(ByteArray::from(bytes))
    }
}

impl<const LENGTH: usize> From<Address<LENGTH>> for [u8; LENGTH] {
    fn from(address: Address<LENGTH>) -> Self {
        address.0.into()
    }
}

impl<const LENGTH: usize> Address<LENGTH> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self(ByteArray::random(rng))
    }
}

impl<const LENGTH: usize> Add<u64> for Address<LENGTH> {
    type Output = Self;

    /// Highly inefficient implementation of an add modulo 2^8^LENGTH in little endian.
    fn add(mut self, mut adder: u64) -> Self::Output {
        let mut carry = 0;
        let mut pos = 0;
        while 0 < carry || adder != 0 {
            // add bytes
            let lhs = &mut self[pos % LENGTH];
            let rhs = adder % 256;
            let res = *lhs as i32 + rhs as i32 + carry;

            // update states
            *lhs = (res % 256) as u8;
            carry = res >> 8;
            adder >>= 8;
            pos += 1;

            if (pos % LENGTH) == 0 {
                carry -= 1;
            }
        }
        self
    }
}

#[cfg(feature = "serialization")]
impl<const LENGTH: usize> Serialize for Address<LENGTH> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "serialization")]
impl<'de, const LENGTH: usize> Deserialize<'de> for Address<LENGTH> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ByteArray::deserialize(deserializer).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use crate::address::Address;

    #[test]
    fn test_add() {
        // Test with one byte overflow.
        // 256 is the neutral element
        assert_eq!(Address::from([0]) + 0, Address::from([0]));
        assert_eq!(Address::from([0]) + 1, Address::from([1]));
        assert_eq!(Address::from([0]) + 256, Address::from([0]));

        // Test with two bytes overflow.
        // 256 is a shift
        assert_eq!(Address::from([0, 0]) + 1, Address::from([1, 0]));
        assert_eq!(Address::from([0, 0]) + 256, Address::from([0, 1]));

        // random add
        assert_eq!(4325 >> 8, 16);
        assert_eq!(4325 % 256, 229);
        assert_eq!(229 + 100 - 256, 73); // there will be a carry
        assert_eq!(Address::from([100, 10]) + 4325, Address::from([73, 27]));

        // 2^16 is the neutral element
        assert_eq!(Address::from([0, 0]) + (1 << 16), Address::from([0, 0]));
    }
}
