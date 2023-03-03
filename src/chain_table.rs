//! This module defines all structures and methods specific to the Chain Table.
//! The Chain Table contains the chains indexed in the Entry Table. A chain is
//! composed of values indexed by Findex and are stored in the Chain Table by
//! blocks. An indexed value can be divided in several blocks of length
//! `BLOCK_LENGTH`. Each Chain Table lines contains `TABLE_WIDTH` blocks. All
//! blocks containing the same indexed value may not be stored in the same Chain
//! Table line.
//!
//! The Chain Table values are encrypted. Each Chain Table values belonging to
//! the same chain are encrypted using the same DEM key.
//!
//! Chain Table UIDs are derived in a way that describes chains:
//! - the first UID is derived from the hash of the keyword associated to the
//!   chain;
//! - the following UIDs are derived from the previous UID;
//! - all UIDs belonging to the same chain are derived using the same KMAC key.

use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializer},
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{Dem, SymKey},
};

use crate::{
    error::CoreError as Error,
    structs::{Block, Uid},
    KeyingMaterial, CHAIN_TABLE_KEY_DERIVATION_INFO,
};

/// Value of the Chain Table. It is composed of a maximum of `TABLE_WIDTH`
/// blocks of length `BLOCK_LENGTH`.
#[must_use]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChainTableValue<const BLOCK_LENGTH: usize>(Vec<Block<BLOCK_LENGTH>>);

impl<const BLOCK_LENGTH: usize> ChainTableValue<BLOCK_LENGTH> {
    /// Creates a new Chain Table value with the given blocks.
    ///
    /// - `blocks`  : blocks to store in this Chain Table entry.
    pub fn new<const TABLE_WIDTH: usize>(blocks: Vec<Block<BLOCK_LENGTH>>) -> Result<Self, Error> {
        if blocks.len() > TABLE_WIDTH {
            return Err(Error::ConversionError(format!(
                "Cannot add more than {TABLE_WIDTH} values inside a `ChainTableValue`"
            )));
        }
        Ok(Self(blocks))
    }

    /// Encrypts the Chain Table value using the given DEM key.
    ///
    /// - `kwi_value`   : DEM key used to encrypt the value
    /// - `rng`         : random number generator
    pub fn encrypt<const TABLE_WIDTH: usize, const KEY_LENGTH: usize, DEM: Dem<KEY_LENGTH>>(
        &self,
        kwi_value: &DEM::Key,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let mut ser = Serializer::with_capacity(BLOCK_LENGTH * TABLE_WIDTH);
        for block in self.iter() {
            ser.write(block)?;
        }
        // Pad the line with empty blocks if needed.
        let padding = Block::<BLOCK_LENGTH>::new_empty_block();
        for _ in self.len()..TABLE_WIDTH {
            ser.write_array(&padding)?;
        }
        DEM::encrypt(rng, kwi_value, &ser.finalize(), None).map_err(Error::from)
    }

    /// Decrypts the Chain Table value using the given DEM key.
    ///
    /// - `kwi_value`   : DEM key used to encrypt the value
    /// - `ciphertext`  : encrypted Chain Table value
    pub fn decrypt<
        const TABLE_WIDTH: usize,
        const DEM_KEY_LENGTH: usize,
        DEM: Dem<DEM_KEY_LENGTH>,
    >(
        kwi_value: &DEM::Key,
        ciphertext: &[u8],
    ) -> Result<Self, Error> {
        if TABLE_WIDTH * BLOCK_LENGTH + DEM::ENCRYPTION_OVERHEAD != ciphertext.len() {
            return Err(Error::CryptoError(format!(
                "invalid ciphertext length: given {}, should be {}",
                ciphertext.len(),
                TABLE_WIDTH * BLOCK_LENGTH + DEM::ENCRYPTION_OVERHEAD
            )));
        }
        let bytes = DEM::decrypt(kwi_value, ciphertext, None)?;
        let mut de = Deserializer::new(&bytes);
        let mut res = Vec::with_capacity(TABLE_WIDTH);
        for _ in 0..TABLE_WIDTH {
            let block = de.read::<Block<BLOCK_LENGTH>>()?;
            // Blocks starting by `0` are padding.
            // There cannot be any meaningful block after a padding block.
            if block[0] == 0 {
                break;
            }
            res.push(block);
        }
        Ok(Self(res))
    }
}

impl<const BLOCK_LENGTH: usize> Deref for ChainTableValue<BLOCK_LENGTH> {
    type Target = Vec<Block<BLOCK_LENGTH>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const BLOCK_LENGTH: usize> DerefMut for ChainTableValue<BLOCK_LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const BLOCK_LENGTH: usize> IntoIterator for ChainTableValue<BLOCK_LENGTH> {
    type IntoIter = std::vec::IntoIter<Block<BLOCK_LENGTH>>;
    type Item = Block<BLOCK_LENGTH>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Chain Table
pub struct ChainTable<const UID_LENGTH: usize, const BLOCK_LENGTH: usize>(
    HashMap<Uid<UID_LENGTH>, ChainTableValue<BLOCK_LENGTH>>,
);

impl<const UID_LENGTH: usize, const BLOCK_LENGTH: usize> ChainTable<UID_LENGTH, BLOCK_LENGTH> {
    /// Derives a Chain Table UID using the given KMAC key and bytes.
    ///
    /// - `key`     : KMAC key
    /// - `bytes`   : bytes from which to derive the UID
    pub fn generate_uid<const KMAC_KEY_LENGTH: usize, KmacKey: SymKey<KMAC_KEY_LENGTH>>(
        key: &KmacKey,
        bytes: &[u8],
    ) -> Uid<UID_LENGTH> {
        kmac!(
            UID_LENGTH,
            key.as_bytes(),
            bytes,
            CHAIN_TABLE_KEY_DERIVATION_INFO
        )
        .into()
    }
}

impl<const UID_LENGTH: usize, const BLOCK_LENGTH: usize> Deref
    for ChainTable<UID_LENGTH, BLOCK_LENGTH>
{
    type Target = HashMap<Uid<UID_LENGTH>, ChainTableValue<BLOCK_LENGTH>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const UID_LENGTH: usize, const BLOCK_LENGTH: usize> DerefMut
    for ChainTable<UID_LENGTH, BLOCK_LENGTH>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const UID_LENGTH: usize, const BLOCK_LENGTH: usize> IntoIterator
    for ChainTable<UID_LENGTH, BLOCK_LENGTH>
{
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = <<Self as Deref>::Target as IntoIterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Maps a chain's keying material `K_wi` to the list of the chain UIDs.
#[must_use]
#[derive(Debug)]
pub struct KwiChainUids<const UID_LENGTH: usize, const KWI_LENGTH: usize>(
    // Use a vector not to shuffle the chain. This is important because indexed
    // values can be divided in blocks that span several lines in the chain.
    HashMap<KeyingMaterial<KWI_LENGTH>, Vec<Uid<UID_LENGTH>>>,
);

impl<const UID_LENGTH: usize, const KEY_LENGTH: usize> Deref
    for KwiChainUids<UID_LENGTH, KEY_LENGTH>
{
    type Target = HashMap<KeyingMaterial<KEY_LENGTH>, Vec<Uid<UID_LENGTH>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const UID_LENGTH: usize, const KEY_LENGTH: usize> DerefMut
    for KwiChainUids<UID_LENGTH, KEY_LENGTH>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const KEY_LENGTH: usize, const UID_LENGTH: usize> Default
    for KwiChainUids<UID_LENGTH, KEY_LENGTH>
{
    fn default() -> Self {
        Self(HashMap::default())
    }
}

impl<const UID_LENGTH: usize, const KEY_LENGTH: usize> KwiChainUids<UID_LENGTH, KEY_LENGTH> {
    /// Creates a `KwiChainUids` with the given `capacity`.
    ///
    /// - `capacity`    : capacity to set
    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        reexport::rand_core::SeedableRng,
        symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, Dem},
        CsRng,
    };

    use super::*;
    use crate::{
        structs::{IndexedValue, Location},
        Keyword, CHAIN_TABLE_KEY_DERIVATION_INFO,
    };

    const KWI_LENGTH: usize = 16;
    const BLOCK_LENGTH: usize = 32;
    const TABLE_WIDTH: usize = 2;

    #[test]
    fn test_encryption() {
        let mut rng = CsRng::from_entropy();
        let kwi = KeyingMaterial::<KWI_LENGTH>::new(&mut rng);
        let kwi_value: <Aes256GcmCrypto as Dem<{ Aes256GcmCrypto::KEY_LENGTH }>>::Key =
            kwi.derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);

        let keyword = Keyword::from("Robert".as_bytes());
        let location = Location::from("Robert's location".as_bytes());
        let indexed_value1 = IndexedValue::from(keyword);
        let indexed_value2 = IndexedValue::from(location);

        let mut chain_table_value1 = ChainTableValue::<BLOCK_LENGTH>::default();
        chain_table_value1.extend_from_slice(&Block::pad(&indexed_value1.to_vec()).unwrap());
        chain_table_value1.extend_from_slice(&Block::pad(&indexed_value2.to_vec()).unwrap());
        // The indexed values should be short enough to fit in a single block.
        assert_eq!(chain_table_value1.len(), 2);

        let mut chain_table_value2 = ChainTableValue::<BLOCK_LENGTH>::default();
        chain_table_value2.extend_from_slice(&Block::pad(&indexed_value1.to_vec()).unwrap());
        // The indexed values should be short enough to fit in a single block.
        assert_eq!(chain_table_value2.len(), 1);

        let c1 = chain_table_value1
            .encrypt::<TABLE_WIDTH, { Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>(
                &kwi_value, &mut rng,
            )
            .unwrap();
        let c2 = chain_table_value2
            .encrypt::<TABLE_WIDTH, { Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>(
                &kwi_value, &mut rng,
            )
            .unwrap();

        let res1 = ChainTableValue::decrypt::<
            TABLE_WIDTH,
            { Aes256GcmCrypto::KEY_LENGTH },
            Aes256GcmCrypto,
        >(&kwi_value, &c1)
        .unwrap();
        let res2 = ChainTableValue::decrypt::<
            TABLE_WIDTH,
            { Aes256GcmCrypto::KEY_LENGTH },
            Aes256GcmCrypto,
        >(&kwi_value, &c2)
        .unwrap();

        assert_eq!(
            chain_table_value1, res1,
            "Wrong decryption for chained keyword"
        );
        assert_eq!(
            chain_table_value2, res2,
            "Wrong decryption for chained location"
        );
    }
}
