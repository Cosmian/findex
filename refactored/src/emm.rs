use std::collections::{HashMap, HashSet};

use zeroize::ZeroizeOnDrop;

use crate::error::Error;

pub trait Emm<const KEY_LENGTH: usize, const TOKEN_LENGTH: usize, CallbackError: std::error::Error>
{
    type Key: ZeroizeOnDrop;

    /// Cryptographically secure token used to index values inside the encrypted
    /// multi-map.
    type Token = [u8; TOKEN_LENGTH];

    /// Type of the values stored inside the EMM.
    type Item;

    /// Variable length value stored inside the encrypted multi-map.
    type Value = HashSet<Self::Item>;

    /// Deterministically derives a `KEY_LENGTH` sized cryptographic key from
    /// the given seed.
    fn derive_keys(&self, seed: &[u8]) -> Self::Key;

    /// Deterministically transforms the given tag into a `TOKEN_LENGTH` sized
    /// cryptographically secure token using the given key. This token can then
    /// be used to index data inside the multi-map.
    ///
    /// In particular, the token should leak no information about the tag.
    fn tokenize(k: &Self::Key, tag: &[u8]) -> Self::Token;

    /// Queries the encrypted multi-map for the given tokens and returns the
    /// decrypted values.
    fn get(
        &self,
        k: &Self::Key,
        tokens: HashSet<Self::Token>,
    ) -> Result<HashMap<Self::Token, Self::Value>, Error<CallbackError>>;

    /// Encrypts the given values using the given key and insert the ciphertexts
    /// into the multi-map.
    fn insert(&mut self, k: &Self::Key, values: HashSet<Self::Token, Self::Value>);
}
