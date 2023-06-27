//! This module defines the structures and methods dedicated to key generation.
//! In Findex, DEM is used to encrypt values and KMAC is used to derive UIDs.
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    kdf256,
    reexport::rand_core::CryptoRngCore,
    SymmetricKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::parameters::{DemKey, KmacKey};

/// Keying Material (KM) used to derive Findex keys.
#[must_use]
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct KeyingMaterial<const LENGTH: usize>([u8; LENGTH]);

impl_byte_array!(KeyingMaterial);

impl<const LENGTH: usize> KeyingMaterial<LENGTH> {
    /// Generates a new random keying material.
    ///
    /// - `rng` : random number generator
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0; LENGTH];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Derives a KMAC key from this keying material.
    ///
    /// # Safety
    ///
    /// The input key material should be of at least 128 bits in order to
    /// guarantee the 128 bits of security.
    #[must_use]
    pub fn derive_kmac_key<const KMAC_KEY_LENGTH: usize>(&self, info: &[u8]) -> KmacKey {
        let mut sk = SymmetricKey::default();
        kdf256!(&mut sk, self, info, b"KMAC key");
        sk
    }

    /// Derives a DEM key from this keying material.
    ///
    /// # Safety
    ///
    /// The input key material should be of at least 128 bits in order to
    /// guarantee the 128 bits of security.
    #[must_use]
    pub fn derive_dem_key(&self, info: &[u8]) -> DemKey {
        let mut sk = SymmetricKey::default();
        kdf256!(&mut sk, self, info, b"DEM key");
        sk
    }
}

impl<const LENGTH: usize> Drop for KeyingMaterial<LENGTH> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const LENGTH: usize> ZeroizeOnDrop for KeyingMaterial<LENGTH> {}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};

    use crate::{parameters::KMAC_KEY_LENGTH, KeyingMaterial};

    #[test]
    fn test_derive_key() {
        let mut rng = CsRng::from_entropy();
        let km = KeyingMaterial::<KMAC_KEY_LENGTH>::new(&mut rng);
        let dem_key = km.derive_dem_key(b"info");
        println!("dem_key: {dem_key:?}");
        let kmac_key = km.derive_kmac_key::<KMAC_KEY_LENGTH>(b"info");
        println!("derived_key: {kmac_key:?}");
        let dem_key = km.derive_dem_key(b"info");
        println!("dem_key: {dem_key:?}");
        let kmac_key = km.derive_kmac_key::<KMAC_KEY_LENGTH>(b"info");
        println!("derived_key: {kmac_key:?}");
    }
}
