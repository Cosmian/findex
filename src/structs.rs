//! This module defines all useful structures used by Findex.

use std::{
    collections::HashMap,
    fmt::Debug,
    ops::{Deref, DerefMut},
    vec::Vec,
};

use cosmian_crypto_core::{
    bytes_ser_de::{to_leb128_len, Deserializer, Serializable, Serializer},
    reexport::rand_core::CryptoRngCore,
};
use tiny_keccak::{Hasher, Sha3};

use crate::error::CoreError as Error;

/// The labels are used to provide additional public information to the hash
/// algorithm when generating Entry Table UIDs.
//
// TODO (TBZ): Should the label size be at least 32-bytes?
#[must_use]
#[derive(Clone, Debug)]
pub struct Label(Vec<u8>);

impl Label {
    /// Generates a new random label of 32 bytes.
    ///
    /// - `rng` : random number generator
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = vec![0; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl_byte_vector!(Label);

/// A [`Keyword`] is a byte vector used to index other values.
#[must_use]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Keyword(Vec<u8>);

impl_byte_vector!(Keyword);

impl Keyword {
    /// Number of bytes used to hash keywords.
    pub const HASH_LENGTH: usize = 32;

    /// Hash this keyword using SHA3-256.
    #[must_use]
    pub fn hash(&self) -> [u8; Self::HASH_LENGTH] {
        let mut hasher = Sha3::v256();
        hasher.update(self);
        let mut bytes = [0; Self::HASH_LENGTH];
        hasher.finalize(&mut bytes);
        for (i, byte) in bytes.into_iter().enumerate() {
            bytes[i] = byte;
        }
        bytes
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum InsertionType {
    Addition,
    Deletion,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum BlockPrefix {
    NonTerminating,
    Terminating { length: u8 },
    Padding,
}

impl From<BlockPrefix> for u8 {
    fn from(value: BlockPrefix) -> Self {
        match value {
            BlockPrefix::NonTerminating => u8::MAX,
            BlockPrefix::Terminating { length } => length,
            BlockPrefix::Padding => 0,
        }
    }
}

impl From<u8> for BlockPrefix {
    fn from(value: u8) -> Self {
        if 0 == value {
            Self::Padding
        } else if u8::MAX == value {
            Self::NonTerminating
        } else {
            Self::Terminating { length: value }
        }
    }
}

/// A `Block` defines a fixed-size block of bytes.
///
/// It is used to store variable length values in the Chain Table by fixed-sized
/// chunks. It allows padding lines to an equal size which avoids leaking
/// information.
///
/// A value can be represented by several blocks. The first blocks representing
/// a value are full. The first byte is set to `u8::MAX`. The last block
/// representing a value may not be full. It is padded with 0s. The first byte
/// is used to write the size of the data stored in this block. The special
/// prefix value `0` means the block contains no data.
///
/// +-------------------------+--------------------------+
/// |        1 byte           | `BLOCK_LENGTH` - 1 bytes |
/// +-------------------------+--------------------------+
/// |      `0` or `u8::MAX`   |                          |
/// |            or           |       padded data        |
/// | number of bytes written |                          |
/// +-------------------------+--------------------------+
///
/// The corollary is that the length of a block shall not be greater than 254
/// (`u8::MAX - 1`); this is enough because bigger blocks imply more wasted
/// space for small values (a small value would be padded to `LENGTH` bytes).
#[must_use]
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct Block<const LENGTH: usize> {
    pub(crate) block_type: InsertionType,
    pub(crate) prefix: BlockPrefix,
    pub(crate) data: [u8; LENGTH],
}

impl<const LENGTH: usize> Block<LENGTH> {
    /// Creates a new `Block` from the given bytes. Terminating blocks are
    /// prepended with the number of bytes written and padded with 0s.
    /// Non-terminating blocks are prepended with `LENGTH`.
    ///
    /// - `block_type`      : addition or deletion
    /// - `bytes`           : bytes to store in the block
    /// - `is_terminating`  : true if the block is the last block of a value
    pub fn new(
        block_type: InsertionType,
        prefix: BlockPrefix,
        bytes: &[u8],
    ) -> Result<Self, Error> {
        if LENGTH > (u8::MAX - 1) as usize {
            return Err(Error::CryptoError(format!(
                "block length should be smaller than {}",
                u8::MAX - 1
            )));
        }
        if LENGTH < bytes.len() {
            return Err(crate::Error::CryptoError(format!(
                "blocks can't hold more than {LENGTH} bytes ({} given)",
                bytes.len()
            )));
        }
        let mut data = [0; LENGTH];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            block_type,
            prefix,
            data,
        })
    }

    /// Returns `true` if this block is an addition, and `false` if it is a
    /// deletion.
    pub fn is_addition(&self) -> bool {
        self.block_type == InsertionType::Addition
    }

    /// Unpads the byte vectors contained in the given list of `Block`.
    ///
    /// - `blocks`  : list of blocks to unpad
    pub fn unpad(blocks: &[Self]) -> Result<Vec<(InsertionType, Vec<u8>)>, Error> {
        let mut blocks = blocks;
        let mut res = Vec::new();
        while !blocks.is_empty() {
            // Try reading blocks until a terminating block is encountered.
            let mut bytes = Vec::with_capacity(LENGTH);
            let block_type = blocks[0].block_type;
            while blocks.len() > 1 && blocks[0].prefix == BlockPrefix::NonTerminating {
                if blocks[0].block_type != block_type {
                    return Err(crate::Error::CryptoError(
                        "mixed block types for a single byte vector".to_string(),
                    ));
                }
                bytes.extend_from_slice(&blocks[0].data);
                blocks = &blocks[1..];
            }
            if BlockPrefix::NonTerminating == blocks[0].prefix {
                return Err(Error::CryptoError(
                    "Last block given is a non-terminating block.".to_string(),
                ));
            }
            if blocks[0].block_type != block_type {
                return Err(crate::Error::CryptoError(
                    "mixed block types for a single byte vector".to_string(),
                ));
            }
            let length = <u8>::from(blocks[0].prefix) as usize;
            bytes.extend_from_slice(&blocks[0].data[..length]);
            blocks = &blocks[1..];
            res.push((block_type, bytes));
        }
        Ok(res)
    }

    /// Pads the given bytes into blocks. Uses the first byte to differentiate
    /// terminating blocks:
    ///
    /// - non-terminating blocks are prefixed by `LENGTH`;
    /// - terminating blocks are prefixed by the actual length written.
    ///
    /// # Parameters
    ///
    /// - `bytes`   : bytes to be padded in to a `Block`
    pub fn pad(block_type: InsertionType, mut bytes: &[u8]) -> Result<Vec<Self>, Error> {
        // Number of blocks needed.
        let mut partition_size = bytes.len() / LENGTH;
        if bytes.len() % LENGTH != 0 {
            partition_size += 1;
        }

        let mut blocks = Vec::with_capacity(partition_size);
        while bytes.len() > LENGTH {
            // this is a non-terminating block
            blocks.push(Self::new(
                block_type,
                BlockPrefix::NonTerminating,
                &bytes[..LENGTH],
            )?);
            bytes = &bytes[LENGTH..];
        }
        blocks.push(Self::new(
            block_type,
            BlockPrefix::Terminating {
                length: <u8>::try_from(bytes.len())?,
            },
            bytes,
        )?);

        Ok(blocks)
    }

    /// Generates a new empty block.
    pub const fn padding_block() -> Self {
        Self {
            block_type: InsertionType::Deletion,
            prefix: BlockPrefix::Padding,
            data: [0; LENGTH],
        }
    }
}

/// A [`Location`] is a vector of bytes describing how to find some data indexed
/// by a [`Keyword`]. It may be a database UID, physical location coordinates of
/// a resources, an URL etc.
#[must_use]
#[derive(Clone, Debug, Hash, Default, PartialEq, Eq)]
pub struct Location(Vec<u8>);

impl_byte_vector!(Location);

/// The value indexed by a [`Keyword`]. It can be either a [`Location`] or
/// another [`Keyword`] in case the searched [`Keyword`] was a tree node.
///
/// When serialized, it is prefixed by `b'l'` if it is a [`Location`] and by
/// `b'w'` if it is a [`Keyword`].
#[must_use]
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum IndexedValue {
    Location(Location),
    NextKeyword(Keyword),
}

impl IndexedValue {
    /// Serializes the [`IndexedValue`].
    ///
    /// The prefix `b'l'` is added if it is a [`Location`]. The prefix `b'w'` is
    /// added if it is a [`Keyword`]. The length of the serialized value is thus
    /// equal to the length of the indexed value + 1.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Location(location) => {
                let mut b = Vec::with_capacity(location.len() + 1);
                b.push(b'l');
                b.extend(&**location);
                b
            }
            Self::NextKeyword(keyword) => {
                let mut b = Vec::with_capacity(keyword.len() + 1);
                b.push(b'w');
                b.extend(&**keyword);
                b
            }
        }
    }

    /// Returns `true` if the [`IndexedValue`] is a [`Location`].
    #[must_use]
    pub const fn is_location(&self) -> bool {
        matches!(self, Self::Location(_))
    }

    /// Returns the underlying [`Location`] if the [`IndexedValue`] is a
    /// [`Location`].
    #[must_use]
    pub const fn get_location(&self) -> Option<&Location> {
        match &self {
            Self::Location(l) => Some(l),
            Self::NextKeyword(_) => None,
        }
    }

    /// Returns `true` if the [`IndexedValue`] is a [`Keyword`].
    #[must_use]
    pub const fn is_keyword(&self) -> bool {
        matches!(self, Self::NextKeyword(_))
    }

    /// Returns the underlying [`Keyword`] if the [`IndexedValue`] is a
    /// [`Keyword`].
    #[must_use]
    pub const fn get_keyword(&self) -> Option<&Keyword> {
        match &self {
            Self::NextKeyword(keyword) => Some(keyword),
            Self::Location(_) => None,
        }
    }
}

impl Default for IndexedValue {
    fn default() -> Self {
        Self::Location(Location::default())
    }
}

/// The reverse implementation of `to_vec()` for [`IndexedValue`].
impl TryFrom<&[u8]> for IndexedValue {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 2 {
            return Err(Error::ConversionError(
                "Invalid Indexed Value: too short".to_string(),
            ));
        }
        match value[0] {
            b'l' => Ok(Self::Location(Location::from(&value[1..]))),
            b'w' => Ok(Self::NextKeyword(Keyword::from(&value[1..]))),
            x => Err(Error::ConversionError(format!(
                "Invalid Indexed Value starting with {x:?}"
            ))),
        }
    }
}

impl From<Location> for IndexedValue {
    fn from(value: Location) -> Self {
        Self::Location(value)
    }
}

impl From<Keyword> for IndexedValue {
    fn from(value: Keyword) -> Self {
        Self::NextKeyword(value)
    }
}

impl TryFrom<IndexedValue> for Location {
    type Error = Error;

    fn try_from(value: IndexedValue) -> Result<Self, Self::Error> {
        match value {
            IndexedValue::Location(location) => Ok(location),
            IndexedValue::NextKeyword(_) => Err(Self::Error::ConversionError(
                "`IndexedValue` is not a `Location`".to_string(),
            )),
        }
    }
}

impl Serializable for IndexedValue {
    type Error = Error;

    fn length(&self) -> usize {
        let length = 1 + match self {
            Self::Location(l) => l.len(),
            Self::NextKeyword(k) => k.len(),
        };
        to_leb128_len(length) + length
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        ser.write_vec(&self.to_vec()).map_err(Self::Error::from)
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        Self::try_from(de.read_vec()?.as_slice())
    }

    fn try_to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        // don't call `write()` to avoir writing size
        Ok(self.to_vec())
    }

    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        // don't call `read()` since there is no leading size
        Self::try_from(bytes)
    }
}

/// Index tables UID type.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Uid<const LENGTH: usize>([u8; LENGTH]);

impl_byte_array!(Uid);

/// An encrypted table maps [`Uid`]s to encrypted values.
// NOTE TBZ: need struct to implement `Serializable`
#[must_use]
#[derive(Default, Debug, Clone)]
pub struct EncryptedTable<const UID_LENGTH: usize>(HashMap<Uid<UID_LENGTH>, Vec<u8>>);

impl<const UID_LENGTH: usize> EncryptedTable<UID_LENGTH> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }
}

impl<const UID_LENGTH: usize> Deref for EncryptedTable<UID_LENGTH> {
    type Target = HashMap<Uid<UID_LENGTH>, Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const UID_LENGTH: usize> DerefMut for EncryptedTable<UID_LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const UID_LENGTH: usize> From<EncryptedTable<UID_LENGTH>>
    for HashMap<Uid<UID_LENGTH>, Vec<u8>>
{
    fn from(encrypted_table: EncryptedTable<UID_LENGTH>) -> Self {
        encrypted_table.0
    }
}

impl<const UID_LENGTH: usize> From<<Self as Deref>::Target> for EncryptedTable<UID_LENGTH> {
    fn from(hashmap: <Self as Deref>::Target) -> Self {
        Self(hashmap)
    }
}

impl<const UID_LENGTH: usize> IntoIterator for EncryptedTable<UID_LENGTH> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = (Uid<UID_LENGTH>, Vec<u8>);

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<const UID_LENGTH: usize> FromIterator<(Uid<UID_LENGTH>, Vec<u8>)>
    for EncryptedTable<UID_LENGTH>
{
    fn from_iter<T: IntoIterator<Item = (Uid<UID_LENGTH>, Vec<u8>)>>(iter: T) -> Self {
        let hashmap = iter.into_iter().collect();
        Self(hashmap)
    }
}

impl<const UID_LENGTH: usize> Serializable for EncryptedTable<UID_LENGTH> {
    type Error = Error;

    fn length(&self) -> usize {
        let mut length = UID_LENGTH * self.len();
        for value in self.values() {
            length += value.len();
        }
        length
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = 0;
        n += ser.write_leb128_u64(self.0.len() as u64)?;
        for (uid, value) in &self.0 {
            n += ser.write_array(uid)?;
            n += ser.write_vec(value)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let length = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut items = HashMap::with_capacity(length);
        for _ in 0..length {
            let key = Uid::from(de.read_array()?);
            let value = de.read_vec()?;
            items.insert(key, value);
        }
        Ok(Self(items))
    }
}

/// Data format used for upsert operations. It contains for each UID upserted
/// the old value (optiona) and the new value:
///
/// UID <-> (`OLD_VALUE`, `NEW_VALUE`)
#[must_use]
pub struct UpsertData<const UID_LENGTH: usize>(
    HashMap<Uid<UID_LENGTH>, (Option<Vec<u8>>, Vec<u8>)>,
);

impl<const UID_LENGTH: usize> UpsertData<UID_LENGTH> {
    /// Build the upsert data from the old and new table.
    ///
    /// - `old_table`   : previous state of the table
    /// - `new_table`   : new state of the table
    pub fn new(
        old_table: &EncryptedTable<UID_LENGTH>,
        new_table: EncryptedTable<UID_LENGTH>,
    ) -> Self {
        Self(
            new_table
                .into_iter()
                .map(|(uid, new_value)| {
                    let old_value = old_table.get(&uid).map(Vec::to_owned);
                    (uid, (old_value, new_value))
                })
                .collect(),
        )
    }
}

impl<const UID_LENGTH: usize> Deref for UpsertData<UID_LENGTH> {
    type Target = HashMap<Uid<UID_LENGTH>, (Option<Vec<u8>>, Vec<u8>)>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const UID_LENGTH: usize> IntoIterator for UpsertData<UID_LENGTH> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = (Uid<UID_LENGTH>, (Option<Vec<u8>>, Vec<u8>));

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<const UID_LENGTH: usize> Serializable for UpsertData<UID_LENGTH> {
    type Error = Error;

    fn length(&self) -> usize {
        self.values()
            .map(|(old_value, new_value)| {
                let old_value_len = old_value.as_ref().map(Vec::len).unwrap_or_default();
                UID_LENGTH
                    + to_leb128_len(old_value_len)
                    + old_value_len
                    + to_leb128_len(new_value.len())
                    + new_value.len()
            })
            .sum()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let empty_vec = vec![];
        let mut n = ser.write_leb128_u64(self.len() as u64)?;
        for (uid, (old_value, new_value)) in self.iter() {
            n += ser.write(uid)?;
            n += ser.write_vec(old_value.as_ref().unwrap_or(&empty_vec))?;
            n += ser.write_vec(new_value)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let length = de.read_leb128_u64()? as usize;
        let mut res = HashMap::with_capacity(length);
        for _ in 0..length {
            let uid = de.read::<Uid<UID_LENGTH>>()?;
            let old_value = de.read_vec()?;
            let new_value = de.read_vec()?;
            let old_value = if old_value.is_empty() {
                None
            } else {
                Some(old_value)
            };
            res.insert(uid, (old_value, new_value));
        }
        Ok(Self(res))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding() {
        const BLOCK_LENGTH: usize = 3;
        // Pad vector with remaining bytes.
        let bytes = vec![1, 2, 3, 4, 5];
        let blocks = Block::<BLOCK_LENGTH>::pad(InsertionType::Addition, &bytes).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(
            blocks,
            vec![
                Block {
                    block_type: InsertionType::Addition,
                    prefix: BlockPrefix::NonTerminating,
                    data: [1, 2, 3]
                },
                Block {
                    block_type: InsertionType::Addition,
                    prefix: BlockPrefix::Terminating { length: 2 },
                    data: [4, 5, 0]
                },
            ]
        );

        let res = Block::<BLOCK_LENGTH>::unpad(&blocks).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0], (InsertionType::Addition, bytes));

        // Pad vector without remaining byte.
        let bytes = vec![1, 2, 3];
        let blocks = Block::<BLOCK_LENGTH>::pad(InsertionType::Addition, &bytes).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            blocks,
            vec![Block {
                block_type: InsertionType::Addition,
                prefix: BlockPrefix::Terminating { length: 3 },
                data: [1, 2, 3]
            },]
        );

        let res = Block::<BLOCK_LENGTH>::unpad(&blocks).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0], (InsertionType::Addition, bytes));

        // Pad vector in one big block
        const BLOCK_LENGTH_2: usize = 32;
        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut blocks = Block::<BLOCK_LENGTH_2>::pad(InsertionType::Addition, &bytes).unwrap();
        assert_eq!(blocks.len(), 1);
        // Append another big block containing the same vector.
        blocks.push(blocks[0]);
        let res = Block::<BLOCK_LENGTH_2>::unpad(&blocks).unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0], (InsertionType::Addition, bytes.clone()));
        assert_eq!(res[1], (InsertionType::Addition, bytes));
    }
}
