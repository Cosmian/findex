use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use cosmian_crypto_core::{
    kdf,
    reexport::rand_core::{RngCore, SeedableRng},
    symmetric_crypto::{
        aes_256_gcm_pure::{
            decrypt_in_place_detached, encrypt_in_place_detached, MAC_LENGTH, NONCE_LENGTH,
        },
        key::Key,
        SymKey,
    },
    CsRng,
};

use crate::{callbacks::FetchChain, edx::Edx, error::Error};

pub struct EncryptedValue<const VALUE_LENGTH: usize> {
    ciphertext: [u8; VALUE_LENGTH],
    nonce: [u8; NONCE_LENGTH],
    tag: [u8; MAC_LENGTH],
}

impl<const VALUE_LENGTH: usize> EncryptedValue<VALUE_LENGTH> {
    fn encrypt(
        key: &[u8],
        value: [u8; VALUE_LENGTH],
    ) -> Result<Self, cosmian_crypto_core::CryptoCoreError> {
        let mut res = Self {
            ciphertext: value,
            nonce: [0; NONCE_LENGTH],
            tag: [0; MAC_LENGTH],
        };
        let mut rng = CsRng::from_entropy();
        rng.fill_bytes(&mut res.nonce);
        encrypt_in_place_detached(key, &mut res.ciphertext, &res.nonce, None)?;
        todo!()
    }

    fn decrypt(
        &self,
        key: &[u8],
    ) -> Result<[u8; VALUE_LENGTH], cosmian_crypto_core::CryptoCoreError> {
        let mut res = self.ciphertext;
        decrypt_in_place_detached(key, &mut res, &self.tag, &self.nonce, None)?;
        Ok(res)
    }
}

/// The Chain Table is functionally an Encrypted Multi-Map. However, it is
/// implemented using an Encrypted Dictionary containing for each value `B`
/// fixed size blocks of bytes.
pub struct ChainTable<
    const TOKEN_LENGTH: usize,
    const BLOCK_LENGTH: usize,
    const LINE_LENGTH: usize,
    CallbackError: std::error::Error,
> where
    [(); BLOCK_LENGTH * LINE_LENGTH]:,
{
    fetch: FetchChain<TOKEN_LENGTH, { BLOCK_LENGTH * LINE_LENGTH }, CallbackError>,
}

impl<
    const KEY_LENGTH: usize,
    const TOKEN_LENGTH: usize,
    const BLOCK_LENGTH: usize,
    const LINE_LENGTH: usize,
    CallbackError: std::error::Error,
> Edx<KEY_LENGTH, TOKEN_LENGTH, LINE_LENGTH, Error<CallbackError>>
    for ChainTable<TOKEN_LENGTH, BLOCK_LENGTH, LINE_LENGTH, CallbackError>
where
    [(); BLOCK_LENGTH * LINE_LENGTH]:,
{
    type EncryptedValue = EncryptedValue<{ BLOCK_LENGTH * LINE_LENGTH }>;
    type Key = Key<KEY_LENGTH>;
    type Token = [u8; TOKEN_LENGTH];
    type Value = [[u8; BLOCK_LENGTH]; LINE_LENGTH];

    fn derive_keys(seed: &[u8]) -> Self::Key {
        Self::Key::from_bytes(kdf!(KEY_LENGTH, seed))
    }

    fn tokenize(k: &Self::Key, tag: &[u8]) -> Self::Token {
        kmac!(TOKEN_LENGTH, k, tag)
    }

    fn get(
        &self,
        tokens: HashSet<Self::Token>,
    ) -> Result<HashMap<Self::Token, Self::EncryptedValue>, Error<CallbackError>> {
        (self.fetch)(tokens).map_err(Error::Callback)
    }

    fn resolve(
        k: &Self::Key,
        encrypted_value: Self::EncryptedValue,
    ) -> Result<Self::Value, Error<CallbackError>> {
        todo!()
    }

    fn upsert(
        &self,
        k: &Self::Key,
        old_values: &HashMap<Self::Token, Self::EncryptedValue>,
        new_values: HashMap<Self::Token, Self::Value>,
    ) -> Result<HashMap<Self::Token, Self::EncryptedValue>, Error<CallbackError>> {
        todo!("The Chain Table does not do any upsert.")
    }

    fn insert(
        k: &Self::Key,
        values: &HashMap<Self::Token, Self::Value>,
    ) -> std::collections::HashSet<[u8; TOKEN_LENGTH]> {
        todo!()
    }
}

impl<
    const TOKEN_LENGTH: usize,
    const BLOCK_LENGTH: usize,
    const LINE_LENGTH: usize,
    CallbackError: std::error::Error,
> ChainTable<TOKEN_LENGTH, BLOCK_LENGTH, LINE_LENGTH, CallbackError>
where
    [(); BLOCK_LENGTH * LINE_LENGTH]:,
{
    /// Transforms the given lists of values into fixed size arrays of values.
    ///
    /// Since the Chain Table is implemented using an Encrypted Dictionary, a
    /// variable number of blocks need to fit inside fixed size lines. This is
    /// why values need to be prepared before inserting them.
    fn prepare<Tag: Hash>(
        values: HashMap<Tag, Vec<Vec<u8>>>,
    ) -> HashMap<Tag, Vec<[[u8; BLOCK_LENGTH]; LINE_LENGTH]>> {
        todo!()
    }
}
