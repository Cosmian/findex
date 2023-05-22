//! The Entry Table is a Encrypted Dictionary scheme (EDX). It is used to
//! securely store constant size values.
//!
//! It uses the AES256-GCM algorithm in order to encrypt its values and the
//! KMAC256 algorithm in order to derive secure tokens from tags.

use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use cosmian_crypto_core::{
    kdf,
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{aes_256_gcm_pure::KEY_LENGTH, key::Key, SymKey},
};

use crate::{
    edx::{Edx, EncryptedValue},
    error::Error,
    parameters::TOKEN_LENGTH,
};

pub trait Callbacks<
    const TOKEN_LENGTH: usize,
    const VALUE_LENGTH: usize,
    CallbackError: std::error::Error,
>
{
    /// Queries a table for the given tokens (UIDs).
    ///
    /// Tokens that do not index any value in the table should not be present in
    /// the returned map.
    ///
    /// # Error
    ///
    /// No error should be returned in case a requested token does not index any
    /// value.
    fn fetch(
        &self,
        tokens: HashSet<[u8; TOKEN_LENGTH]>,
    ) -> Result<HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>, CallbackError>;

    /// Upserts the given values into the Entry Table.
    ///
    /// The upsert operation on each token should be *atomic* and *conditional*:
    /// - if there is no value in both the set of old values and the encrypted
    ///   dictionary, inserts the new value;
    /// - if there is a value in the set of old values that matches the value in
    ///   the encrypted dictionary, replaces it by the new value;
    /// - if there is a value in the set of old values that does not match the
    ///   value in the encrypted dictionary, returns the encrypted value stored;
    /// - if there is a value in the set of old values but no value in the
    ///   encrypted dictionary, returns an error.
    fn upsert(
        &mut self,
        old_values: &HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>,
        new_values: HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>,
    ) -> Result<HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>, CallbackError>;
}

pub struct EntryTable<
    const VALUE_LENGTH: usize,
    CallbackError: std::error::Error,
    Database: Callbacks<TOKEN_LENGTH, VALUE_LENGTH, CallbackError>,
> {
    db: Database,
    err: PhantomData<CallbackError>,
}

impl<
    const VALUE_LENGTH: usize,
    CallbackError: std::error::Error,
    Database: Callbacks<TOKEN_LENGTH, VALUE_LENGTH, CallbackError>,
> EntryTable<VALUE_LENGTH, CallbackError, Database>
{
    pub fn new(db: Database) -> Self {
        Self {
            db,
            err: Default::default(),
        }
    }
}

impl<
    const VALUE_LENGTH: usize,
    CallbackError: std::error::Error,
    Database: Callbacks<TOKEN_LENGTH, VALUE_LENGTH, CallbackError>,
> Edx<KEY_LENGTH, TOKEN_LENGTH, VALUE_LENGTH, Error<CallbackError>>
    for EntryTable<VALUE_LENGTH, CallbackError, Database>
{
    fn gen_seed(&self, rng: &mut impl CryptoRngCore) -> [u8; KEY_LENGTH] {
        let mut seed = [0; KEY_LENGTH];
        rng.fill_bytes(&mut seed);
        seed
    }

    // TODO (TBZ): add info in the derivation.
    fn derive_key(&self, seed: &[u8]) -> Self::Key {
        Self::Key {
            token: Key::from_bytes(kdf!(KEY_LENGTH, seed)),
            value: Key::from_bytes(kdf!(KEY_LENGTH, seed)),
        }
    }

    // TODO (TBZ): add info in the derivation.
    fn tokenize(&self, k: &Self::Key, tag: &[u8]) -> Self::Token {
        kmac!(TOKEN_LENGTH, &k.token, tag)
    }

    fn get(
        &self,
        tokens: HashSet<Self::Token>,
    ) -> Result<HashMap<Self::Token, Self::EncryptedValue>, Error<CallbackError>> {
        self.db.fetch(tokens).map_err(Error::Callback)
    }

    fn resolve(
        &self,
        k: &Self::Key,
        encrypted_value: Self::EncryptedValue,
    ) -> Result<Self::Value, Error<CallbackError>> {
        encrypted_value.decrypt(&k.value).map_err(Error::CryptoCore)
    }

    fn upsert(
        &mut self,
        rng: &mut impl CryptoRngCore,
        k: &Self::Key,
        old_values: &HashMap<Self::Token, Self::EncryptedValue>,
        new_values: HashMap<Self::Token, Self::Value>,
    ) -> Result<HashMap<Self::Token, Self::EncryptedValue>, Error<CallbackError>> {
        let new_values = new_values
            .into_iter()
            .map(|(token, value)| Ok((token, Self::EncryptedValue::encrypt(rng, &k.value, value)?)))
            .collect::<Result<HashMap<_, _>, Error<CallbackError>>>()?;
        self.db
            .upsert(old_values, new_values)
            .map_err(Error::Callback)
    }

    fn insert(
        &mut self,
        rng: &mut impl CryptoRngCore,
        k: &Self::Key,
        values: HashMap<Self::Token, Self::Value>,
    ) -> Result<HashSet<Self::Token>, Error<CallbackError>> {
        panic!("The Entry Table does not do any insert")
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Display;

    use cosmian_crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };

    use super::*;
    use crate::edx::EncryptedValue;

    const VALUE_LENGTH: usize = 32;

    #[derive(Debug)]
    struct CallbackError(String);

    impl Display for CallbackError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "callback error")
        }
    }

    impl std::error::Error for CallbackError {}

    #[derive(Default)]
    struct Table(HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>);

    impl Callbacks<TOKEN_LENGTH, VALUE_LENGTH, CallbackError> for Table {
        fn fetch(
            &self,
            tokens: HashSet<[u8; TOKEN_LENGTH]>,
        ) -> Result<HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>, CallbackError>
        {
            Ok(tokens
                .into_iter()
                .filter_map(|t| self.0.get(&t).cloned().map(|v| (t, v)))
                .collect())
        }

        fn upsert(
            &mut self,
            old_values: &HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>,
            new_values: HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>,
        ) -> Result<HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>, CallbackError>
        {
            let mut res = HashMap::new();
            for (token, new_ciphertext) in new_values {
                let old_ciphertext = old_values.get(&token);
                let ciphertext = self.0.get(&token);

                if let Some(ciphertext) = ciphertext {
                    if let Some(old_ciphertext) = old_ciphertext {
                        if old_ciphertext == ciphertext {
                            self.0.insert(token, new_ciphertext.clone());
                        } else {
                            res.insert(token, ciphertext.clone());
                        }
                    } else {
                        res.insert(token, ciphertext.clone());
                    }
                } else if old_ciphertext.is_none() {
                    self.0.insert(token, new_ciphertext.clone());
                } else {
                    return Err(CallbackError(format!(
                        "no ciphertext found for token {token:?}"
                    )));
                }
            }

            Ok(res)
        }
    }

    #[test]
    fn test_edx() {
        let mut rng = CsRng::from_entropy();

        let mut table = EntryTable::new(Table::default());
        let seed = table.gen_seed(&mut rng);
        let key = table.derive_key(&seed);

        let tag = "only value";
        let token = table.tokenize(&key, tag.as_bytes());

        let mut value = [0; VALUE_LENGTH];
        rng.fill_bytes(&mut value);

        table
            .upsert(
                &mut rng,
                &key,
                &HashMap::new(),
                HashMap::from_iter([(token, value)]),
            )
            .unwrap();

        let res = table.get(HashSet::from_iter([token])).unwrap();

        assert_eq!(res.len(), 1);

        for (_, ciphertext) in res {
            let decrypted_value = table.resolve(&key, ciphertext).unwrap();
            assert_eq!(decrypted_value, value);
        }
    }
}
