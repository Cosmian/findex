use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::{reexport::rand_core::CryptoRngCore, symmetric_crypto::key::Key};
use zeroize::ZeroizeOnDrop;

pub struct EdxKey<const KEY_LENGTH: usize> {
    pub token: Key<KEY_LENGTH>,
    pub value: Key<KEY_LENGTH>,
}

impl<const KEY_LENGTH: usize> ZeroizeOnDrop for EdxKey<KEY_LENGTH> {}

pub trait Edx<
    const KEY_LENGTH: usize,
    const TOKEN_LENGTH: usize,
    const VALUE_LENGTH: usize,
    Error: std::error::Error,
>
{
    /// Cryptographically secure key.
    type Key: ZeroizeOnDrop;

    /// Cryptographically secure token used to index values inside the encrypted
    /// dictionary.
    type Token = [u8; TOKEN_LENGTH];

    /// Fixed length value stored inside the dictionary.
    type Value;

    /// Fixed length encrypted value stored inside the encrypted dictionary.
    type EncryptedValue;

    /// Deterministically derives a cryptographic key from the given seed.
    fn derive_key(&self, seed: &[u8]) -> Self::Key;

    /// Deterministically transforms the given tag into a token using the given
    /// key. The token should leak no information about the tag.
    fn tokenize(&self, k: &Self::Key, tag: &[u8]) -> Self::Token;

    /// Queries the encrypted dictionary for the given tokens and returns the
    /// encrypted values.
    fn get(
        &self,
        tokens: HashSet<Self::Token>,
    ) -> Result<HashMap<Self::Token, Self::EncryptedValue>, Error>;

    /// Decrypts the given value with the given key.
    fn resolve(
        &self,
        k: &Self::Key,
        encrypted_value: Self::EncryptedValue,
    ) -> Result<Self::Value, Error>;

    /// Encrypts the given new values and conditionally upsert them into the
    /// encrypted dictionary.
    ///
    /// For each new values:
    /// - if there is no value in both the set of old values and the encrypted
    ///   dictionary, inserts the new value;
    /// - if there is a value in the set of old values that matches the value in
    ///   the encrypted dictionary, replaces it by the new value;
    /// - if there is a value in the set of old values that does not match the
    ///   value in the encrypted dictionary, returns the encrypted value stored;
    /// - if there is a value in the set of old values but no value in the
    ///   encrypted dictionary, returns an error.
    ///
    /// All modifications to the encrypted dictionary are *atomic*.
    fn upsert(
        &self,
        rng: &mut impl CryptoRngCore,
        k: &Self::Key,
        old_values: &HashMap<Self::Token, Self::EncryptedValue>,
        new_values: HashMap<Self::Token, Self::Value>,
    ) -> Result<HashMap<Self::Token, Self::EncryptedValue>, Error>;

    /// Encrypts the given values and inserts them into the Encrypted Dictionary
    /// if no value is already stored for the corresponding tokens. Returns the
    /// set of tokens for which a value is already stored.
    fn insert(
        &self,
        rng: &mut impl CryptoRngCore,
        k: &Self::Key,
        values: HashMap<Self::Token, Self::Value>,
    ) -> Result<HashSet<Self::Token>, Error>;
}
