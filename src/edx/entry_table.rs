//! The Entry Table is an Encrypted Dictionary scheme (EDX). It is used to
//! securely store chain metadata.
//!
//! It uses the AES256-GCM algorithm in order to encrypt its values and the
//! KMAC256 algorithm in order to derive secure tokens from tags.

use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
};

use async_trait::async_trait;
use cosmian_crypto_core::{kdf256, reexport::rand_core::CryptoRngCore, SymmetricKey};

use super::{
    structs::{EdxKey, Seed, Token},
    TokenDump,
};
use crate::{
    edx::{DbInterface, DxEnc},
    parameters::{SEED_LENGTH, TOKEN_LENGTH},
    EncryptedValue, Error, Label,
};

/// Implementation of the Entry Table EDX.
#[derive(Debug)]
pub struct EntryTable<const VALUE_LENGTH: usize, Edx: DbInterface<VALUE_LENGTH>>(pub Edx);

impl<const VALUE_LENGTH: usize, Edx: DbInterface<VALUE_LENGTH>> Deref
    for EntryTable<VALUE_LENGTH, Edx>
{
    type Target = Edx;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const ENTRY_TABLE_KEY_DERIVATION_INFO: &[u8] = b"Entry Table key derivation info.";

#[async_trait(?Send)]
impl<const VALUE_LENGTH: usize, Edx: DbInterface<VALUE_LENGTH>> DxEnc<VALUE_LENGTH>
    for EntryTable<VALUE_LENGTH, Edx>
{
    type EncryptedValue = EncryptedValue<VALUE_LENGTH>;
    type Error = Error<Edx::Error>;
    type Key = EdxKey;
    type Seed = Seed<SEED_LENGTH>;
    type Database = Edx;

    fn setup(edx: Self::Database) -> Self {
        Self(edx)
    }

    fn gen_seed(&self, rng: &mut impl CryptoRngCore) -> Self::Seed {
        Seed::new(rng)
    }

    fn derive_keys(&self, seed: &Self::Seed) -> Self::Key {
        let mut kmac_key = SymmetricKey::default();
        kdf256!(
            &mut *kmac_key,
            seed.as_ref(),
            ENTRY_TABLE_KEY_DERIVATION_INFO,
            b"KMAC key"
        );
        let mut aead_key = SymmetricKey::default();
        kdf256!(
            &mut *aead_key,
            seed.as_ref(),
            ENTRY_TABLE_KEY_DERIVATION_INFO,
            b"DEM key"
        );
        Self::Key {
            token: kmac_key,
            value: aead_key,
        }
    }

    fn tokenize(&self, key: &Self::Key, bytes: &[u8], label: Option<&Label>) -> Token {
        if let Some(label) = label {
            kmac!(TOKEN_LENGTH, &key.token, bytes, label).into()
        } else {
            kmac!(TOKEN_LENGTH, &key.token, bytes, &[]).into()
        }
    }

    async fn get(
        &self,
        tokens: HashSet<Token>,
    ) -> Result<Vec<(Token, Self::EncryptedValue)>, Self::Error> {
        self.0
            .fetch(tokens.into())
            .await
            .map_err(Self::Error::from)
            .map(Into::into)
    }

    fn resolve(
        &self,
        key: &Self::Key,
        encrypted_value: &Self::EncryptedValue,
    ) -> Result<[u8; VALUE_LENGTH], Self::Error> {
        encrypted_value.decrypt(&key.value).map_err(Error::from)
    }

    async fn upsert(
        &self,
        old_values: HashMap<Token, Self::EncryptedValue>,
        new_values: HashMap<Token, Self::EncryptedValue>,
    ) -> Result<HashMap<Token, Self::EncryptedValue>, Self::Error> {
        self.0
            .upsert(old_values.into(), new_values.into())
            .await
            .map_err(Self::Error::from)
            .map(Into::into)
    }

    async fn insert(&self, items: HashMap<Token, Self::EncryptedValue>) -> Result<(), Self::Error> {
        self.0
            .insert(items.into())
            .await
            .map_err(Error::DbInterface)
    }

    fn prepare(
        &self,
        rng: &mut impl CryptoRngCore,
        key: &Self::Key,
        value: [u8; VALUE_LENGTH],
    ) -> Result<Self::EncryptedValue, Self::Error> {
        Self::EncryptedValue::encrypt(rng, &key.value, value).map_err(Error::from)
    }

    async fn delete(&self, items: HashSet<Token>) -> Result<(), Self::Error> {
        self.0
            .delete(items.into())
            .await
            .map_err(Self::Error::DbInterface)
    }
}

#[async_trait(?Send)]
impl<const VALUE_LENGTH: usize, Edx: DbInterface<VALUE_LENGTH>> TokenDump
    for EntryTable<VALUE_LENGTH, Edx>
{
    type Error = <Self as DxEnc<VALUE_LENGTH>>::Error;

    async fn dump_tokens(&self) -> Result<HashSet<Token>, Self::Error> {
        self.0
            .dump_tokens()
            .await
            .map_err(Error::DbInterface)
            .map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };

    use super::*;
    use crate::edx::in_memory::InMemoryDb;

    const VALUE_LENGTH: usize = 32;

    #[actix_rt::test]
    async fn test_edx() {
        let mut rng = CsRng::from_entropy();

        let table = EntryTable::setup(InMemoryDb::default());
        let seed = table.gen_seed(&mut rng);
        let key = table.derive_keys(&seed);
        let label = Label::random(&mut rng);

        let tag = "only value";
        let token = table.tokenize(&key, tag.as_bytes(), Some(&label));

        let mut value = [0; VALUE_LENGTH];
        rng.fill_bytes(&mut value);

        let encrypted_value = table.prepare(&mut rng, &key, value).unwrap();
        table
            .upsert(
                HashMap::new(),
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
