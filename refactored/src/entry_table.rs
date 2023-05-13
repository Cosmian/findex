use std::collections::{HashMap, HashSet};

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

use crate::{
    callbacks::{FetchEntry, UpsertEntry},
    edx::Edx,
    error::Error,
};

/// Encrypted value contained inside the Entry Table. It is composed of the
/// AESGCM-256 encrypted value, the nonce used and the corresponding MAC tag.
pub struct EncryptedValue<const VALUE_LENGTH: usize> {
    ciphertext: [u8; VALUE_LENGTH],
    tag: [u8; MAC_LENGTH],
    nonce: [u8; NONCE_LENGTH],
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

pub struct EntryTable<
    const TOKEN_LENGTH: usize,
    const VALUE_LENGTH: usize,
    CallbackError: std::error::Error,
> {
    fetch: FetchEntry<TOKEN_LENGTH, VALUE_LENGTH, CallbackError>,
    upsert: UpsertEntry<TOKEN_LENGTH, VALUE_LENGTH, CallbackError>,
}

impl<
    const KEY_LENGTH: usize,
    const TOKEN_LENGTH: usize,
    const VALUE_LENGTH: usize,
    CallbackError: std::error::Error,
> Edx<KEY_LENGTH, TOKEN_LENGTH, VALUE_LENGTH, Error<CallbackError>>
    for EntryTable<TOKEN_LENGTH, VALUE_LENGTH, CallbackError>
{
    type EncryptedValue = EncryptedValue<VALUE_LENGTH>;
    type Key = Key<KEY_LENGTH>;
    type Token = [u8; TOKEN_LENGTH];
    type Value = [u8; VALUE_LENGTH];

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
        encrypted_value.decrypt(k).map_err(Error::CryptoCoreError)
    }

    fn upsert(
        &self,
        k: &Self::Key,
        old_values: &HashMap<Self::Token, Self::EncryptedValue>,
        new_values: HashMap<Self::Token, Self::Value>,
    ) -> Result<HashMap<Self::Token, Self::EncryptedValue>, Error<CallbackError>> {
        let new_values = new_values
            .into_iter()
            .map(|(token, value)| Ok((token, Self::EncryptedValue::encrypt(k, value)?)))
            .collect::<Result<HashMap<_, _>, Error<CallbackError>>>()?;
        (self.upsert)(old_values, &new_values).map_err(Error::Callback)
    }

    fn insert(
        &self,
        k: &Self::Key,
        values: HashMap<Self::Token, Self::Value>,
    ) -> Result<HashSet<Self::Token>, Error<CallbackError>> {
        todo!("The Entry Table does not do any insert")
    }
}
