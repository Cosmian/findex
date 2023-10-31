//! Implements the Chain Table algorithm.
//!
//! This algorithm is in charge of storing the lists of values indexed by
//! Findex. Formally, it implements an Encrypted Dictionary (EDX) scheme.
//!
//! The encryption scheme used is AES256-GCM.

use std::{
    collections::{HashMap, HashSet},
    ops::Deref,
};

use async_trait::async_trait;
use cosmian_crypto_core::{kdf256, reexport::rand_core::CryptoRngCore, SymmetricKey};

use super::structs::Token;
use crate::{
    edx::{
        structs::{EdxKey, Seed},
        DxEnc, EdxStore,
    },
    error::Error,
    parameters::{SEED_LENGTH, TOKEN_LENGTH},
    EncryptedValue, Label,
};

/// Chain Table representation.
#[derive(Debug)]
pub struct ChainTable<const VALUE_LENGTH: usize, Edx: EdxStore<VALUE_LENGTH>>(pub Edx);

impl<const VALUE_LENGTH: usize, Edx: EdxStore<VALUE_LENGTH>> Deref
    for ChainTable<VALUE_LENGTH, Edx>
{
    type Target = Edx;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const CHAIN_TABLE_KEY_DERIVATION_INFO: &[u8] = b"Chain Table key derivation info.";

#[async_trait(?Send)]
impl<const VALUE_LENGTH: usize, EdxScheme: EdxStore<VALUE_LENGTH>> DxEnc<VALUE_LENGTH>
    for ChainTable<VALUE_LENGTH, EdxScheme>
{
    type EncryptedValue = EncryptedValue<VALUE_LENGTH>;
    type Error = Error<EdxScheme::Error>;
    type Key = EdxKey;
    type Seed = Seed<SEED_LENGTH>;
    type Store = EdxScheme;

    fn setup(edx: Self::Store) -> Self {
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
            CHAIN_TABLE_KEY_DERIVATION_INFO,
            b"KMAC key"
        );
        let mut aead_key = SymmetricKey::default();
        kdf256!(
            &mut aead_key,
            seed.as_ref(),
            CHAIN_TABLE_KEY_DERIVATION_INFO,
            b"DEM key"
        );
        Self::Key {
            token: kmac_key,
            value: aead_key,
        }
    }

    fn tokenize(&self, key: &Self::Key, bytes: &[u8], _label: Option<&Label>) -> Token {
        kmac!(
            TOKEN_LENGTH,
            &key.token,
            bytes,
            CHAIN_TABLE_KEY_DERIVATION_INFO
        )
        .into()
    }

    async fn get(
        &self,
        tokens: HashSet<Token>,
    ) -> Result<Vec<(Token, Self::EncryptedValue)>, Self::Error> {
        self.0.fetch(tokens).await.map_err(Error::Callback)
    }

    fn resolve(
        &self,
        key: &Self::Key,
        encrypted_value: &Self::EncryptedValue,
    ) -> Result<[u8; VALUE_LENGTH], Self::Error> {
        encrypted_value.decrypt(&key.value).map_err(Error::from)
    }

    fn prepare(
        &self,
        rng: &mut impl CryptoRngCore,
        key: &Self::Key,
        value: [u8; VALUE_LENGTH],
    ) -> Result<Self::EncryptedValue, Self::Error> {
        Self::EncryptedValue::encrypt(rng, &key.value, value).map_err(Error::from)
    }

    async fn upsert(
        &self,
        _old_values: &HashMap<Token, Self::EncryptedValue>,
        _new_values: HashMap<Token, Self::EncryptedValue>,
    ) -> Result<HashMap<Token, Self::EncryptedValue>, Self::Error> {
        panic!("The Chain Table does not do any upsert.")
    }

    async fn insert(&self, items: HashMap<Token, Self::EncryptedValue>) -> Result<(), Self::Error> {
        self.0.insert(items).await.map_err(Error::Callback)
    }

    async fn delete(&self, items: HashSet<Token>) -> Result<(), Self::Error> {
        self.0.delete(items).await.map_err(Error::Callback)
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

        let table = ChainTable::setup(InMemoryEdx::default());
        let seed = table.gen_seed(&mut rng);
        let key = table.derive_keys(&seed);
        let label = Label::random(&mut rng);

        let tag = "only value";
        let token = table.tokenize(&key, tag.as_bytes(), Some(&label));

        let mut value = [0; VALUE_LENGTH];
        rng.fill_bytes(&mut value);

        let encrypted_value = table.prepare(&mut rng, &key, value).unwrap();

        table
            .insert(HashMap::from_iter([(token, encrypted_value)]))
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
