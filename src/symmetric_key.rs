use std::ops::{Deref, DerefMut};

use tiny_keccak::{Hasher, Sha3};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Secret;

/// A type that holds symmetric key of a fixed  size.
///
/// It is internally built using an array of bytes of the given length.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey<const LENGTH: usize>(Secret<LENGTH>);

impl<const LENGTH: usize> Deref for SymmetricKey<LENGTH> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const LENGTH: usize> DerefMut for SymmetricKey<LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const LENGTH: usize> Default for SymmetricKey<LENGTH> {
    fn default() -> Self {
        Self(Secret::new())
    }
}

impl<const LENGTH: usize> From<SymmetricKey<LENGTH>> for Zeroizing<Vec<u8>> {
    fn from(value: SymmetricKey<LENGTH>) -> Self {
        Self::new(value.0.to_vec())
    }
}

impl<const KEY_LENGTH: usize> SymmetricKey<KEY_LENGTH> {
    /// Deterministically derive a new key from the given secret and additional
    /// information.
    ///
    /// # Error
    ///
    /// Fails to generate the key in case the secret evidently does not contain
    /// enough entropy. The check performed is based on the respective key
    /// and secret lengths. The secret needs to be generated from a source
    /// containing enough entropy (greater than its length) for this check
    /// to be valid.
    pub fn derive<const SECRET_LENGTH: usize>(
        secret: &Secret<SECRET_LENGTH>,
        info: &[u8],
    ) -> Result<Self, String> {
        if SECRET_LENGTH < KEY_LENGTH {
            return Err(format!(
                "insufficient entropy to derive {KEY_LENGTH}-byte key from a {SECRET_LENGTH}-byte \
                 secret",
            ));
        }
        let mut key = Self::default();
        let mut hash = Sha3::v256();
        hash.update(secret);
        hash.update(info);
        hash.finalize(&mut key);
        Ok(key)
    }
}
