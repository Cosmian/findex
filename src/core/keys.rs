//! This module defines the structures and methods dedicated to key generation.
//! In Findex, DEM is used to encrypt values and KMAC is used to derive UIDs.

use std::collections::HashMap;

use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    kdf,
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::SymKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Keying Material (KM) used to derive Findex keys.
#[must_use]
#[derive(Clone, Hash, Eq, PartialEq)]
pub struct KeyingMaterial<const LENGTH: usize>([u8; LENGTH]);

impl_byte_array!(KeyingMaterial);

impl<const LENGTH: usize> KeyingMaterial<LENGTH> {
    /// Generates a new random keying material.
    ///
    /// - `rng` : random number generator
    #[inline]
    pub(crate) fn new(rng: &mut impl CryptoRngCore) -> Self {
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
    #[inline]
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
    #[inline]
    pub(crate) fn derive_dem_key<const DEM_KEY_LENGTH: usize, DemKey: SymKey<DEM_KEY_LENGTH>>(
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

/// Cache mapping keying materials to their derived KMAC and DEM keys.
pub struct KeyCache<
    const MATERIAL_LENGTH: usize,
    const KMAC_KEY_LENGTH: usize,
    const DEM_KEY_LENGTH: usize,
    KmacKey: SymKey<KMAC_KEY_LENGTH>,
    DemKey: SymKey<DEM_KEY_LENGTH>,
>(HashMap<KeyingMaterial<MATERIAL_LENGTH>, (KmacKey, DemKey)>);

impl<
    const MATERIAL_LENGTH: usize,
    const KMAC_KEY_LENGTH: usize,
    const DEM_KEY_LENGTH: usize,
    KmacKey: SymKey<KMAC_KEY_LENGTH>,
    DemKey: SymKey<DEM_KEY_LENGTH>,
> KeyCache<MATERIAL_LENGTH, KMAC_KEY_LENGTH, DEM_KEY_LENGTH, KmacKey, DemKey>
{
    #[inline]
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    /// Gets the entry corresponding to the given keying material. Creates it if
    /// needed.
    ///
    /// - `keying_material` : keying material
    /// - `info`            : information used to derive the keys
    pub(crate) fn get_entry_or_insert(
        &mut self,
        keying_material: &KeyingMaterial<MATERIAL_LENGTH>,
        info: &[u8],
    ) -> &mut (KmacKey, DemKey) {
        if !self.0.contains_key(keying_material) {
            self.0.insert(
                keying_material.clone(),
                (
                    keying_material.derive_kmac_key(info),
                    keying_material.derive_dem_key(info),
                ),
            );
        }
        self.0.get_mut(keying_material).unwrap()
    }
}
