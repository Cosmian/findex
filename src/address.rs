use std::ops::{Deref, DerefMut};

use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address<const LENGTH: usize>([u8; LENGTH]);

impl<const LENGTH: usize> Deref for Address<LENGTH> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LENGTH: usize> DerefMut for Address<LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LENGTH: usize> Address<LENGTH> {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut res = Self([0; LENGTH]);
        rng.fill_bytes(&mut res);
        res
    }
}
