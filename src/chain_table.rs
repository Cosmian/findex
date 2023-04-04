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
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    reexport::rand_core::CryptoRngCore,
    symmetric_crypto::{Dem, SymKey},
};

use crate::{
    error::CoreError as Error,
    structs::{Block, BlockPrefix, BlockType, Uid},
    KeyingMaterial, CHAIN_TABLE_KEY_DERIVATION_INFO,
};

/// Due to the flag byte implementation (see the `Serializable` implementation
/// for `ChainTableValue`), no more than 8 `Block`s can be added to a
/// `ChainTableValue`.
pub const MAX_CHAIN_TABLE_WIDTH: usize = 8;

/// Value of the Chain Table. It is composed of a maximum of `TABLE_WIDTH`
/// blocks of length `BLOCK_LENGTH`.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainTableValue<const TABLE_WIDTH: usize, const BLOCK_LENGTH: usize> {
    length: usize,
    blocks: [Block<BLOCK_LENGTH>; TABLE_WIDTH],
}

impl<const TABLE_WIDTH: usize, const BLOCK_LENGTH: usize> Default
    for ChainTableValue<TABLE_WIDTH, BLOCK_LENGTH>
{
    fn default() -> Self {
        Self {
            length: 0,
            blocks: [<Block<BLOCK_LENGTH>>::padding_block(); TABLE_WIDTH],
        }
    }
}

impl<const TABLE_WIDTH: usize, const BLOCK_LENGTH: usize>
    ChainTableValue<TABLE_WIDTH, BLOCK_LENGTH>
{
    /// This checks that the `TABLE_WIDTH` does not exceed the
    /// `MAX_CHAIN_TABLE_WIDTH`.
    pub const CHECK_TABLE_WIDTH: () = assert!(
        !(TABLE_WIDTH > MAX_CHAIN_TABLE_WIDTH),
        "`CHAIN_TABLE_WIDTH` should *not* be greater than 8",
    );

    /// Pushes new blocks to the Chain Table value.
    ///
    /// Pushing an addition sets to 1 the corresponding bit in the flag byte.
    ///
    /// # Parameters
    ///
    /// - blocks:   blocks to add
    pub fn try_pushing_blocks(&mut self, blocks: &[Block<BLOCK_LENGTH>]) -> Result<(), Error> {
        if self.length + blocks.len() > TABLE_WIDTH {
            return Err(Error::ConversionError(format!(
                "cannot store more than {TABLE_WIDTH} blocks inside a `ChainTableValue`"
            )));
        }
        self.blocks[self.length..self.length + blocks.len()].copy_from_slice(blocks);
        self.length += blocks.len();
        Ok(())
    }

    /// Returns a slice over the non-padding blocks of this Chain Table value.
    pub fn as_blocks(&self) -> &[Block<BLOCK_LENGTH>] {
        &self.blocks[..self.length]
    }

    /// Encrypts the Chain Table value using the given DEM key.
    ///
    /// - `kwi_value`   : DEM key used to encrypt the value
    /// - `rng`         : random number generator
    pub fn encrypt<const KEY_LENGTH: usize, DEM: Dem<KEY_LENGTH>>(
        &self,
        kwi_value: &DEM::Key,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let bytes = self.try_to_bytes()?;
        DEM::encrypt(rng, kwi_value, &bytes, None).map_err(Error::from)
    }

    /// Decrypts the Chain Table value using the given DEM key.
    ///
    /// - `kwi_value`   : DEM key used to encrypt the value
    /// - `ciphertext`  : encrypted Chain Table value
    pub fn decrypt<const DEM_KEY_LENGTH: usize, DEM: Dem<DEM_KEY_LENGTH>>(
        kwi_value: &DEM::Key,
        ciphertext: &[u8],
    ) -> Result<Self, Error> {
        let max_ciphertext_length = 1 + TABLE_WIDTH * (1 + BLOCK_LENGTH) + DEM::ENCRYPTION_OVERHEAD;
        if max_ciphertext_length != ciphertext.len() {
            return Err(Error::CryptoError(format!(
                "invalid ciphertext length: given {}, should be {}",
                ciphertext.len(),
                max_ciphertext_length
            )));
        }
        let bytes = DEM::decrypt(kwi_value, ciphertext, None)?;
        Self::try_from_bytes(&bytes)
    }
}

impl<const TABLE_WIDTH: usize, const BLOCK_LENGTH: usize> Serializable
    for ChainTableValue<TABLE_WIDTH, BLOCK_LENGTH>
{
    type Error = Error;

    fn length(&self) -> usize {
        // The leading byte corresponds to the flag byte.
        1 + TABLE_WIDTH * (1 + BLOCK_LENGTH)
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut flag = 0u8;
        for i in 0..self.length {
            // Set the corresponding bit to 1 in the flag byte.
            if self.blocks[i].is_addition() {
                flag += 1 << i;
            }
        }
        let mut n = ser.write_array(&[flag])?;
        for block in self.blocks {
            n += ser.write_array(&[<u8>::from(block.prefix)])?;
            n += ser.write_array(&block.data)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let mut res = Self::default();
        let flag = de.read_array::<1>()?[0];
        for i in 0..TABLE_WIDTH {
            let prefix = BlockPrefix::from(de.read_array::<1>()?[0]);
            let data = de.read_array::<BLOCK_LENGTH>()?;
            if BlockPrefix::Padding != prefix {
                let block_type = if (flag >> i) % 2 == 1 {
                    BlockType::Addition
                } else {
                    BlockType::Deletion
                };
                res.try_pushing_blocks(&[Block {
                    block_type,
                    prefix,
                    data,
                }])?;
            }
        }
        Ok(res)
    }
}

/// Chain Table
pub struct ChainTable<const UID_LENGTH: usize, const TABLE_WIDTH: usize, const BLOCK_LENGTH: usize>(
    HashMap<Uid<UID_LENGTH>, ChainTableValue<TABLE_WIDTH, BLOCK_LENGTH>>,
);

impl<const UID_LENGTH: usize, const TABLE_WIDTH: usize, const BLOCK_LENGTH: usize>
    ChainTable<UID_LENGTH, TABLE_WIDTH, BLOCK_LENGTH>
{
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

impl<const UID_LENGTH: usize, const TABLE_WIDTH: usize, const BLOCK_LENGTH: usize> Default
    for ChainTable<UID_LENGTH, TABLE_WIDTH, BLOCK_LENGTH>
{
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<const UID_LENGTH: usize, const TABLE_WIDTH: usize, const BLOCK_LENGTH: usize> Deref
    for ChainTable<UID_LENGTH, TABLE_WIDTH, BLOCK_LENGTH>
{
    type Target = HashMap<Uid<UID_LENGTH>, ChainTableValue<TABLE_WIDTH, BLOCK_LENGTH>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const UID_LENGTH: usize, const TABLE_WIDTH: usize, const BLOCK_LENGTH: usize> DerefMut
    for ChainTable<UID_LENGTH, TABLE_WIDTH, BLOCK_LENGTH>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const UID_LENGTH: usize, const TABLE_WIDTH: usize, const BLOCK_LENGTH: usize> IntoIterator
    for ChainTable<UID_LENGTH, TABLE_WIDTH, BLOCK_LENGTH>
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
    const CHAIN_TABLE_WIDTH: usize = 2;

    #[test]
    fn test_serialization() {
        let indexed_value_1 = IndexedValue::from(Location::from("location1".as_bytes()));
        let indexed_value_2 = IndexedValue::from(Location::from("location2".as_bytes()));
        let mut chain_table_value = ChainTableValue::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH>::default();
        for block in indexed_value_1.to_blocks(BlockType::Addition).unwrap() {
            chain_table_value.try_pushing_blocks(&[block]).unwrap();
        }
        let bytes = chain_table_value.try_to_bytes().unwrap();
        assert_eq!(chain_table_value.length(), bytes.len());
        let res = ChainTableValue::try_from_bytes(&bytes).unwrap();
        assert_eq!(chain_table_value, res);
        for block in indexed_value_2.to_blocks(BlockType::Addition).unwrap() {
            chain_table_value.try_pushing_blocks(&[block]).unwrap();
        }
        let bytes = chain_table_value.try_to_bytes().unwrap();
        assert_eq!(chain_table_value.length(), bytes.len());
        let res = ChainTableValue::try_from_bytes(&bytes).unwrap();
        assert_eq!(chain_table_value, res);
    }

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

        let mut chain_table_value1 = ChainTableValue::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH>::default();
        for block in indexed_value1.to_blocks(BlockType::Addition).unwrap() {
            chain_table_value1.try_pushing_blocks(&[block]).unwrap();
        }
        for block in indexed_value2.to_blocks(BlockType::Deletion).unwrap() {
            chain_table_value1.try_pushing_blocks(&[block]).unwrap();
        }
        // The indexed values should be short enough to fit in a single block.
        assert_eq!(chain_table_value1.length, 2);

        let mut chain_table_value2 = ChainTableValue::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH>::default();
        for block in indexed_value1.to_blocks(BlockType::Addition).unwrap() {
            chain_table_value2.try_pushing_blocks(&[block]).unwrap();
        }
        // The indexed values should be short enough to fit in a single block.
        assert_eq!(chain_table_value2.length, 1);

        let c1 = chain_table_value1
            .encrypt::<{ Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>(&kwi_value, &mut rng)
            .unwrap();
        let c2 = chain_table_value2
            .encrypt::<{ Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>(&kwi_value, &mut rng)
            .unwrap();

        let res1 = ChainTableValue::decrypt::<{ Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>(
            &kwi_value, &c1,
        )
        .unwrap();
        let res2 = ChainTableValue::decrypt::<{ Aes256GcmCrypto::KEY_LENGTH }, Aes256GcmCrypto>(
            &kwi_value, &c2,
        )
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
