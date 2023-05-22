//! Implements the Chain Table algorithm.
//!
//! This algorithm is in charge of storing the lists of values indexed by
//! Findex. Formally, it implements an Encrypted Multi-Map (EMM) scheme.
//! However, the data structure is an Encrypted Dictionary (EDX) which
//! characteristic is to store fixed length values.
//!
//! TODO: give a rational of this implementation choice
//!
//! In order to fit variable size lists of variable size values, a double
//! padding is used:
//! - the variable size values are padded into fixed size *blocks*;
//! - the lists of blocks are padded into fixed size *lines*.
//! This padding is performed by the `prepare` method.
//!
//! The encryption scheme used in AES256-GCM.
//!
//! TODO: the nonce used to encrypt the values should be derived from the token
//! to avoid storing yet another random value.

use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::{
    kdf,
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{aes_256_gcm_pure::KEY_LENGTH, key::Key, SymKey},
};

use crate::{
    callbacks::{FetchChain, InsertChain},
    edx::Edx,
    error::Error,
    parameters::TOKEN_LENGTH,
};

/// Chain Table representation.
pub struct ChainTable<const VALUE_LENGTH: usize, CallbackError: std::error::Error> {
    fetch: FetchChain<TOKEN_LENGTH, VALUE_LENGTH, CallbackError>,
    insert: InsertChain<TOKEN_LENGTH, VALUE_LENGTH, CallbackError>,
}

impl<const VALUE_LENGTH: usize, CallbackError: std::error::Error>
    Edx<KEY_LENGTH, TOKEN_LENGTH, VALUE_LENGTH, Error<CallbackError>>
    for ChainTable<VALUE_LENGTH, CallbackError>
{
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
        (self.fetch)(tokens).map_err(Error::Callback)
    }

    fn resolve(
        &self,
        k: &Self::Key,
        encrypted_value: Self::EncryptedValue,
    ) -> Result<Self::Value, Error<CallbackError>> {
        encrypted_value.decrypt(&k.value).map_err(Error::CryptoCore)
    }

    fn upsert(
        &self,
        rng: &mut impl CryptoRngCore,
        k: &Self::Key,
        old_values: &HashMap<Self::Token, Self::EncryptedValue>,
        new_values: HashMap<Self::Token, Self::Value>,
    ) -> Result<HashMap<Self::Token, Self::EncryptedValue>, Error<CallbackError>> {
        todo!("The Chain Table does not do any upsert.")
    }

    fn insert(
        &self,
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
        (self.insert)(encrypted_values).map_err(Error::Callback)
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
