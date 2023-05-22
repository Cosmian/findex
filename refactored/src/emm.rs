use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::symmetric_crypto::key::Key;
use zeroize::ZeroizeOnDrop;

pub trait Emm<const KEY_LENGTH: usize, const TOKEN_LENGTH: usize> {
    type Key: ZeroizeOnDrop;

    /// Cryptographically secure token used to index values inside the encrypted
    /// multi-map.
    type Token = [u8; TOKEN_LENGTH];

    /// Type of the values stored inside the EMM.
    type Item;

    /// Variable length value stored inside the encrypted multi-map.
    type Value = Vec<Self::Item>;

    /// Deterministically derives a `KEY_LENGTH` sized cryptographic key from
    /// the given seed.
    fn derive_keys(seed: &[u8]) -> Key<KEY_LENGTH>;

    /// Deterministically transforms the given tag into a `TOKEN_LENGTH` sized
    /// cryptographically secure token using the given key. This token can then
    /// be used to index data inside the multi-map.
    ///
    /// In particular, the token should leak no information about the tag.
    fn tokenize(k: &Key<KEY_LENGTH>, tag: &[u8]) -> Self::Token;

    /// Queries the encrypted multi-map for the given tokens and returns the
    /// decrypted values.
    fn get(
        k: &Key<KEY_LENGTH>,
        tokens: HashSet<Self::Token>,
    ) -> HashMap<Self::Token, Vec<Self::Value>>;

    /// Encrypts the given values using the given key and insert the ciphertexts
    /// into the multi-map.
    fn insert(k: &Key<KEY_LENGTH>, values: HashSet<Self::Token, Vec<Self::Value>>);

    /// Encrypts the given values using the given key and insert the ciphertexts
    /// into the multi-map.
    fn remove(k: &Key<KEY_LENGTH>, values: HashSet<Self::Token, Vec<Self::Value>>);
}
