use std::ops::Add;

use cosmian_crypto_core::define_byte_type;

// An address is a little-endian number encoded on LENGTH bytes.
define_byte_type!(Address);

impl<const LENGTH: usize> Copy for Address<LENGTH> {}

impl<const LENGTH: usize> Add<u64> for Address<LENGTH> {
    type Output = Self;

    /// Highly inefficient implementation of an add modulo 2^8^LENGTH in little
    /// endian.
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

#[cfg(test)]
mod tests {
    use crate::address::Address;

    #[test]
    fn test_add() {
        //
        // Test with one byte overflow.
        //
        let a0 = Address::from([0]);
        let a1 = Address::from([1]);
        assert_eq!(a0 + 0, a0);
        assert_eq!(a0 + 1, a1);
        assert_eq!(a0 + 256, a0); // 256 is the neutral element

        //
        // Test with two bytes overflow.
        //
        let a00 = Address::from([0, 0]);
        let a01 = Address::from([0, 1]);
        let a10 = Address::from([1, 0]);
        assert_eq!(a00 + 1, a10);
        assert_eq!(a00 + 256, a01); // 256 is a shift

        //
        // random add
        //
        assert_eq!(4325 >> 8, 16);
        assert_eq!(4325 % 256, 229);
        assert_eq!(229 + 100 - 256, 73); // there will be a carry
        assert_eq!(Address::from([100, 10]) + 4325, Address::from([73, 27]));
        // 2^16 is the neutral element
        assert_eq!(Address::from([0, 0]) + (1 << 16), Address::from([0, 0]));
    }
}
