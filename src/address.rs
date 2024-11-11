use std::ops::{Add, Deref, DerefMut};

use rand_core::CryptoRngCore;
#[cfg(feature = "cloudproof")]
use redis::{RedisWrite, ToRedisArgs};
use std::fmt;

// NOTE: a more efficient implementation of the address could be a big-int.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address<const LENGTH: usize>([u8; LENGTH]);

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

impl<const LENGTH: usize> Default for Address<LENGTH> {
    fn default() -> Self {
        Self([0; LENGTH])
    }
}

impl<const LENGTH: usize> Address<LENGTH> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut res = Self([0; LENGTH]);
        rng.fill_bytes(&mut *res);
        res
    }
}

impl<const LENGTH: usize> Add<u64> for Address<LENGTH> {
    type Output = Address<LENGTH>;

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

#[cfg(feature = "cloudproof")]
impl<const N: usize> fmt::Display for Address<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0)
    }
}

#[cfg(feature = "cloudproof")]
impl<const N: usize> ToRedisArgs for Address<N> {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        out.write_arg(self.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use crate::address::Address;

    #[test]
    fn test_add() {
        // Test with one byte overflow.
        assert_eq!(Address([0]) + 0, Address([0]));
        assert_eq!(Address([0]) + 1, Address([1]));
        assert_eq!(Address([0]) + 256, Address([0])); // 256 is the neutral element

        // Test with two bytes overflow.
        assert_eq!(Address([0, 0]) + 1, Address([1, 0]));
        assert_eq!(Address([0, 0]) + 256, Address([0, 1])); // 256 is a shift

        // random add
        assert_eq!(4325 >> 8, 16);
        assert_eq!(4325 % 256, 229);
        assert_eq!(229 + 100 - 256, 73); // there will be a carry
        assert_eq!(Address([100, 10]) + 4325, Address([73, 27]));

        assert_eq!(Address([0, 0]) + (1 << 16), Address([0, 0])); // 2^16 is the neutral element
    }
}
