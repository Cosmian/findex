//! The Entry Table is an Encrypted Dictionary scheme (EDX). It is used to
//! securely store chain metadata.
//!
//! It uses the AES256-GCM algorithm in order to encrypt its values and the
//! KMAC256 algorithm in order to derive secure tokens from tags.

use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
};

use async_trait::async_trait;
use cosmian_crypto_core::{kdf256, reexport::rand_core::CryptoRngCore, SymmetricKey};

use super::{
    structs::{EdxKey, Seed},
    TokenDump,
};
use crate::{
    edx::{DxEnc, EdxStore},
    parameters::{SEED_LENGTH, TOKEN_LENGTH},
    EncryptedValue, Error, Label,
};

/// Implementation of the Entry Table EDX.
pub struct EntryTable<const VALUE_LENGTH: usize, Edx: EdxStore<VALUE_LENGTH>>(pub Edx);

impl<const VALUE_LENGTH: usize, Edx: EdxStore<VALUE_LENGTH>> Deref
    for EntryTable<VALUE_LENGTH, Edx>
{
    type Target = Edx;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const ENTRY_TABLE_KEY_DERIVATION_INFO: &[u8] = b"Entry Table key derivation info.";

#[async_trait]
impl<
        const VALUE_LENGTH: usize,
        Edx: EdxStore<VALUE_LENGTH, EncryptedValue = EncryptedValue<VALUE_LENGTH>>,
    > DxEnc<VALUE_LENGTH> for EntryTable<VALUE_LENGTH, Edx>
{
    type EncryptedValue = Edx::EncryptedValue;
    type Error = Error<Edx::Error>;
    type Key = EdxKey;
    type Seed = Seed<SEED_LENGTH>;
    type Store = Edx;
    type Token = Edx::Token;

    fn setup(edx: Self::Store) -> Self {
        Self(edx)
    }

    fn gen_seed(&self, rng: &mut impl CryptoRngCore) -> Self::Seed {
        Seed::new(rng)
    }

    fn derive_keys(&self, seed: &Self::Seed) -> Self::Key {
        let mut kmac_key = SymmetricKey::default();
        kdf256!(
            kmac_key.deref_mut(),
            seed.as_ref(),
            ENTRY_TABLE_KEY_DERIVATION_INFO,
            b"KMAC key"
        );
        let mut aead_key = SymmetricKey::default();
        kdf256!(
            aead_key.deref_mut(),
            seed.as_ref(),
            ENTRY_TABLE_KEY_DERIVATION_INFO,
            b"DEM key"
        );
        Self::Key {
            token: kmac_key,
            value: aead_key,
        }
    }

    fn tokenize<Tag: ?Sized + AsRef<[u8]>>(
        &self,
        key: &Self::Key,
        tag: &Tag,
        label: Option<&Label>,
    ) -> Self::Token {
        kmac!(TOKEN_LENGTH, &key.token, tag.as_ref(), label.unwrap()).into()
    }

    async fn get(
        &self,
        tokens: HashSet<Self::Token>,
    ) -> Result<Vec<(Self::Token, Self::EncryptedValue)>, Self::Error> {
        self.0.fetch(tokens).await.map_err(Self::Error::from)
    }

    fn resolve(
        &self,
        key: &Self::Key,
        encrypted_value: &Self::EncryptedValue,
    ) -> Result<[u8; VALUE_LENGTH], Self::Error> {
        encrypted_value.decrypt(&key.value).map_err(Error::from)
    }

    async fn upsert(
        &mut self,
        old_values: &HashMap<Self::Token, Self::EncryptedValue>,
        new_values: HashMap<Self::Token, Self::EncryptedValue>,
    ) -> Result<HashMap<Self::Token, Self::EncryptedValue>, Self::Error> {
        self.0
            .upsert(old_values, new_values)
            .await
            .map_err(Self::Error::from)
    }

    async fn insert(
        &mut self,
        _values: HashMap<Self::Token, Self::EncryptedValue>,
    ) -> Result<(), Self::Error> {
        panic!("The Entry Table does not do any insert.")
    }

    fn prepare(
        &self,
        rng: &mut impl CryptoRngCore,
        key: &Self::Key,
        value: [u8; VALUE_LENGTH],
    ) -> Result<Self::EncryptedValue, Self::Error> {
        Self::EncryptedValue::encrypt(rng, &key.value, value).map_err(Error::from)
    }

    async fn delete(&mut self, items: HashSet<Self::Token>) -> Result<(), Self::Error> {
        self.0.delete(items).await.map_err(Self::Error::Callback)
    }
}

#[async_trait]
impl<
        const VALUE_LENGTH: usize,
        Edx: EdxStore<VALUE_LENGTH, EncryptedValue = EncryptedValue<VALUE_LENGTH>>,
    > TokenDump for EntryTable<VALUE_LENGTH, Edx>
{
    type Error = <Self as DxEnc<VALUE_LENGTH>>::Error;
    type Token = <Self as DxEnc<VALUE_LENGTH>>::Token;

    async fn dump_tokens(&self) -> Result<HashSet<Self::Token>, Self::Error> {
        self.0.dump_tokens().await.map_err(Error::Callback)
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };

    use super::*;
    use crate::edx::in_memory::InMemoryEdx;

    const VALUE_LENGTH: usize = 32;

    #[actix_rt::test]
    async fn test_edx() {
        let mut rng = CsRng::from_entropy();

        let mut table = EntryTable::setup(InMemoryEdx::default());
        let seed = table.gen_seed(&mut rng);
        let key = table.derive_keys(&seed);
        let label = Label::random(&mut rng);

        let tag = "only value";
        let token = table.tokenize(&key, tag, Some(&label));

        let mut value = [0; VALUE_LENGTH];
        rng.fill_bytes(&mut value);

        let encrypted_value = table.prepare(&mut rng, &key, value).unwrap();
        table
            .upsert(
                &HashMap::new(),
                HashMap::from_iter([(token, encrypted_value)]),
            )
            .await
            .unwrap();

        let res = table
            .get(HashSet::from_iter([token]))
            .await
            .unwrap()
            .into_iter()
            .collect::<HashMap<_, _>>();

        assert_eq!(res.len(), 1);
        let ciphertext = res.get(&token).unwrap();
        let decrypted_value = table.resolve(&key, ciphertext).unwrap();
        assert_eq!(decrypted_value, value);
    }
}
