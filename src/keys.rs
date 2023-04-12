//! This module defines the structures and methods dedicated to key generation.
//! In Findex, DEM is used to encrypt values and KMAC is used to derive UIDs.

use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    kdf,
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::SymKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    pub fn derive_kmac_key<const KMAC_KEY_LENGTH: usize, KmacKey: SymKey<KMAC_KEY_LENGTH>>(
        &self,
        info: &[u8],
    ) -> KmacKey {
        let bytes = kdf!(KMAC_KEY_LENGTH, self, info, b"KMAC key");
        KmacKey::from_bytes(bytes)
    }

    /// Derives a DEM key from this keying material.
    ///
    /// # Safety
    ///
    /// The input key material should be of at least 128 bits in order to
    /// guarantee the 128 bits of security.
    #[must_use]
    pub fn derive_dem_key<const DEM_KEY_LENGTH: usize, DemKey: SymKey<DEM_KEY_LENGTH>>(
        &self,
        info: &[u8],
    ) -> DemKey {
        let bytes = kdf!(DEM_KEY_LENGTH, self, info, b"DEM key");
        DemKey::from_bytes(bytes)
    }
}

impl<const LENGTH: usize> Drop for KeyingMaterial<LENGTH> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const LENGTH: usize> ZeroizeOnDrop for KeyingMaterial<LENGTH> {}
