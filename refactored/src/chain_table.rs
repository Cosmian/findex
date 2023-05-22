//! Implements the Chain Table algorithm.
//!
//! This algorithm is in charge of storing the lists of values indexed by
//! Findex. Formally, it implements an Encrypted Dictionary (EDX) scheme.
//!
//! The encryption scheme used in AES256-GCM.

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

    /// Inserts the given values into the table.
    ///
    /// # Error
    ///
    /// An error should be returned if a value already exists for a given token.
    fn insert(
        &mut self,
        tokens: HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>,
    ) -> Result<HashSet<[u8; TOKEN_LENGTH]>, CallbackError>;
}

/// Chain Table representation.
pub struct ChainTable<
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
> ChainTable<VALUE_LENGTH, CallbackError, Database>
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
    for ChainTable<VALUE_LENGTH, CallbackError, Database>
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
        panic!("The Chain Table does not do any upsert.")
    }

    fn insert(
        &mut self,
        rng: &mut impl CryptoRngCore,
        k: &Self::Key,
        values: HashMap<Self::Token, Self::Value>,
    ) -> Result<HashSet<[u8; TOKEN_LENGTH]>, Error<CallbackError>> {
        let encrypted_values = values
            .into_iter()
            .map(|(token, value)| -> Result<_, _> {
                Ok((token, Self::EncryptedValue::encrypt(rng, &k.value, value)?))
            })
            .collect::<Result<HashMap<_, _>, Error<CallbackError>>>()?;
        self.db.insert(encrypted_values).map_err(Error::Callback)
    }
}

//impl<const VALUE_LENGTH: usize, CallbackError: std::error::Error>
//ChainTable<VALUE_LENGTH, CallbackError>
//{
///// Transforms the given list of variable size values into a list of fixed
///// size lines.
/////
///// This is done using two successive paddings:
///// - values are padded into fixed size blocks;
///// - blocks are padded into fixed size lines.
/////
///// TODO: this may be done in one loop only by iterating over the values and
///// the lines independently.
/////
///// TODO: values may not need to be padded into fixed size blocks first.
//pub fn prepare(
//&self,
//values: &[Vec<u8>],
//) -> Result<Vec<[u8; VALUE_LENGTH]>, Error<CallbackError>> {
//let n_blocks = values
//.iter()
//.map(|v| v.len() / BLOCK_LENGTH + usize::from(v.len() % BLOCK_LENGTH != 0))
//.sum::<usize>();

//// Pads values into blocks.
//let mut blocks = Vec::with_capacity(n_blocks);
//for value in values {
//let (q, r) = (value.len() / BLOCK_LENGTH, value.len() % BLOCK_LENGTH);
//for i in 0..q {
//let mut block = [0; BLOCK_LENGTH + 1];
//block[0] = u8::MAX;
//block[1..].copy_from_slice(&value[i * q..(i + q) * q]);
//blocks.push(block);
//}
//if r != 0 {
//let mut block = [0; BLOCK_LENGTH + 1];
//block[0] = u8::try_from(r)?;
//block[1..r + 1].copy_from_slice(&value[q * BLOCK_LENGTH..]);
//blocks.push(block);
//}

//// Pads blocks into lines.
//let (q, r) = (blocks.len() / LINE_LENGTH, blocks.len() % LINE_LENGTH);
//let mut res = Vec::with_capacity(q + usize::from(r != 0));
//for i in 0..q {
//let mut line = [0; (BLOCK_LENGTH + 1) * LINE_LENGTH];
//for j in 0..LINE_LENGTH {
//line[i + (BLOCK_LENGTH + 1)..(j + 1) * (BLOCK_LENGTH + 1)]
//.copy_from_slice(&blocks[i * LINE_LENGTH + j]);
//}
//res.push(line);
//}
//if r != 0 {
//let mut line = [0; (BLOCK_LENGTH + 1) * LINE_LENGTH];
//for j in 0..r {
//line[q + (BLOCK_LENGTH + 1)..(j + 1) * (BLOCK_LENGTH + 1)]
//.copy_from_slice(&blocks[q * LINE_LENGTH + j]);
//}
//res.push(line);
//}
//Ok(res)
//}
//

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
    struct CallbackError;

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

        fn insert(
            &mut self,
            tokens: HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>,
        ) -> Result<HashSet<[u8; TOKEN_LENGTH]>, CallbackError> {
            let failed_uids = tokens
                .into_iter()
                .filter_map(|(token, value)| {
                    let old_value = self.0.insert(token, value);
                    old_value.map(|_| token)
                })
                .collect::<HashSet<_>>();
            Ok(failed_uids)
        }
    }

    #[test]
    fn test_edx() {
        let mut rng = CsRng::from_entropy();

        let mut table = ChainTable::new(Table::default());
        let seed = table.gen_seed(&mut rng);
        let key = table.derive_key(&seed);

        let tag = "only value";
        let token = table.tokenize(&key, tag.as_bytes());

        let mut value = [0; VALUE_LENGTH];
        rng.fill_bytes(&mut value);

        table
            .insert(&mut rng, &key, HashMap::from_iter([(token, value)]))
            .unwrap();

        let res = table.get(HashSet::from_iter([token])).unwrap();

        assert_eq!(res.len(), 1);

        for (_, ciphertext) in res {
            let decrypted_value = table.resolve(&key, ciphertext).unwrap();
            assert_eq!(decrypted_value, value);
        }
    }
}
