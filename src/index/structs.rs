//! Structures used by the `Index` interface of `Findex`.

use cosmian_crypto_core::{reexport::rand_core::CryptoRngCore, SymmetricKey};

use crate::USER_KEY_LENGTH;

pub type UserKey = SymmetricKey<USER_KEY_LENGTH>;

/// The label is used to provide additional public information to the hash
/// algorithm when generating Entry Table UIDs.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label(Vec<u8>);

impl Label {
    /// Generates a new random label of 32 bytes.
    ///
    /// - `rng` : random number generator
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = vec![0; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl_byte_vector!(Label);

/// A [`Keyword`] is a byte vector used to index other values.
#[must_use]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Keyword(Vec<u8>);

impl_byte_vector!(Keyword);

/// A [`Location`] is a vector of bytes describing how to find some data indexed
/// by a [`Keyword`]. It may be a database UID, physical location coordinates of
/// a resources, an URL etc.
#[must_use]
#[derive(Clone, Debug, Hash, Default, PartialEq, Eq)]
pub struct Location(Vec<u8>);

impl_byte_vector!(Location);
