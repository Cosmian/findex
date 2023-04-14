//! This module defines all useful structures used by Findex.

use std::{
    collections::{hash_map::IntoKeys, HashMap, HashSet},
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
        bytes
    }
}

/// Type of a keyword hash.
pub type KeywordHash = [u8; Keyword::HASH_LENGTH];

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum BlockType {
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
        match value {
            0 => Self::Padding,
            u8::MAX => Self::NonTerminating,
            length => Self::Terminating { length },
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
/// |        1 byte           |      `BLOCK_LENGTH`      |
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
    pub(crate) block_type: BlockType,
    pub(crate) prefix: BlockPrefix,
    pub(crate) data: [u8; LENGTH],
}

/// A block length should be a valid `u8` to allow writing in one byte, and the
/// value `u8::MAX` is reserved to indicate a non-terminating block.
const MAX_BLOCK_LENGTH: usize = (u8::MAX - 1) as usize;

impl<const LENGTH: usize> Block<LENGTH> {
    /// This checks that the `BLOCK_LENGTH` does not exceed the
    /// `MAX_BLOCK_LENGTH`.
    pub const CHECK_LENGTH: () = assert!(
        LENGTH <= MAX_BLOCK_LENGTH,
        "`BLOCK_LENGTH` should be *not* be greater than 254",
    );

    /// Creates a new `Block` from the given bytes. Terminating blocks are
    /// prepended with the number of bytes written and padded with 0s.
    /// Non-terminating blocks are prepended with `LENGTH`.
    ///
    /// - `block_type`      : addition or deletion
    /// - `bytes`           : bytes to store in the block
    /// - `is_terminating`  : true if the block is the last block of a value
    pub fn new(block_type: BlockType, prefix: BlockPrefix, bytes: &[u8]) -> Result<Self, Error> {
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
        self.block_type == BlockType::Addition
    }

    /// Generates a new padding block.
    pub const fn padding_block() -> Self {
        Self {
            // A deletion is ignored when computing the flag.
            block_type: BlockType::Deletion,
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

    /// Extracts `IndexedValue`s from the given `Block`s.
    ///
    /// Reads the `Block`s *in order* until a non-terminating `Block` is found.
    /// Converts the `Block`s read into an `IndexedValue` and adds it to the
    /// results if the `Block`s read were additions. Otherwise removes it from
    /// the results.
    ///
    /// Repeats this process until all the given `Block`s are read.
    ///
    /// # Parameters
    ///
    /// - `blocks`  : list of `Block`s to read from
    pub fn from_blocks<'a, const BLOCK_LENGTH: usize>(
        blocks: impl IntoIterator<Item = &'a Block<BLOCK_LENGTH>>,
    ) -> Result<HashSet<Self>, Error> {
        let mut blocks = blocks.into_iter();

        // There is no simple way to know the number of `IndexedValue`s beforehand.
        let mut indexed_values = HashSet::new();

        while let Some(mut block) = blocks.next() {
            let block_type = block.block_type;
            let mut byte_vector = Vec::with_capacity(BLOCK_LENGTH);

            // Read blocks until a terminating block is encountered.
            while block.prefix == BlockPrefix::NonTerminating {
                byte_vector.extend(block.data);
                block = blocks.next().ok_or(Error::CryptoError(
                    "last block is a non-terminating block".to_string(),
                ))?;
                if block.block_type != block_type {
                    return Err(crate::Error::CryptoError(
                        "mixed block types for a single byte vector".to_string(),
                    ));
                }
            }

            // This block is terminating the byte vector.
            let length = <u8>::from(block.prefix) as usize;
            if length != 0 {
                // This block is not padding.
                byte_vector.extend(&block.data[..length]);
                let value = Self::try_from_bytes(&byte_vector)?;
                if BlockType::Addition == block_type {
                    indexed_values.insert(value);
                } else {
                    indexed_values.remove(&value);
                }
            }
        }

        Ok(indexed_values)
    }

    /// Pads the given `IndexedValue` into blocks of `BLOCK_LENGTH` bytes. The
    /// last chunk is padded with `0`s if needed.
    ///
    /// # Parameters
    ///
    /// - `block_type`  : a block can be an addition or a deletion
    pub fn to_blocks<const BLOCK_LENGTH: usize>(
        &self,
        block_type: BlockType,
    ) -> Result<Vec<Block<BLOCK_LENGTH>>, Error> {
        // TODO (TBZ): implement this conversion without copy.
        let bytes = self.to_vec();

        let mut n_blocks = bytes.len() / BLOCK_LENGTH;
        if bytes.len() % BLOCK_LENGTH != 0 {
            n_blocks += 1;
        }

        let mut blocks = Vec::with_capacity(n_blocks);
        let mut pos = 0;
        while bytes.len() - pos > BLOCK_LENGTH {
            blocks.push(Block::new(
                block_type,
                BlockPrefix::NonTerminating,
                &bytes[pos..pos + BLOCK_LENGTH],
            )?);
            pos += BLOCK_LENGTH;
        }
        blocks.push(Block::new(
            block_type,
            BlockPrefix::Terminating {
                length: <u8>::try_from(bytes.len() - pos)?,
            },
            &bytes[pos..],
        )?);

        Ok(blocks)
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
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

    pub fn into_keys(self) -> IntoKeys<Uid<UID_LENGTH>, Vec<u8>> {
        self.0.into_keys()
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

impl<const UID_LENGTH: usize> FromIterator<Self> for EncryptedTable<UID_LENGTH> {
    fn from_iter<T: IntoIterator<Item = Self>>(iter: T) -> Self {
        let hashmap = iter.into_iter().flat_map(|v| v.0).collect();
        Self(hashmap)
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

/// Data format used for upsert operations.
///
/// It contains for each upserted UID the old value (optional) and the new
/// value:
///
/// UID <-> (`OLD_VALUE`, `NEW_VALUE`)
///
/// Successful upsert operations replace the old value with the new value on
/// lines with the given UIDs. An upsert operation fails if the old value passed
/// does not correspond to the actual value stored (an old value set to `None`
/// corresponds to the value of a line that does not exist yet).
///
/// **Warning**: upsert operations should be *atomic* in order to guarantee
/// their correctness.
#[must_use]
pub struct UpsertData<const UID_LENGTH: usize>(
    HashMap<Uid<UID_LENGTH>, (Option<Vec<u8>>, Vec<u8>)>,
);

impl<const UID_LENGTH: usize> UpsertData<UID_LENGTH> {
    /// Build the upsert data from the old and new tables.
    ///
    /// - `old_table`   : previous state of the table
    /// - `new_table`   : new state of the table
    pub fn new(
        old_table: &EncryptedTable<UID_LENGTH>,
        new_table: EncryptedTable<UID_LENGTH>,
    ) -> Self {
        let mut res: <Self as Deref>::Target = old_table
            .iter()
            .filter_map(|(uid, old_value)| {
                if new_table.get(uid).is_none() {
                    Some((*uid, (Some(old_value.clone()), Vec::new())))
                } else {
                    None
                }
            })
            .collect();
        res.extend(new_table.into_iter().map(|(uid, new_value)| {
            let old_value = old_table.get(&uid).map(Vec::to_owned);
            (uid, (old_value, new_value))
        }));
        Self(res)
    }
}

impl<const UID_LENGTH: usize> Deref for UpsertData<UID_LENGTH> {
    type Target = HashMap<Uid<UID_LENGTH>, (Option<Vec<u8>>, Vec<u8>)>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const UID_LENGTH: usize> DerefMut for UpsertData<UID_LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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

#[cfg(feature = "live_compact")]
pub struct ChainData<const UID_LENGTH: usize> {
    pub(crate) chain_uids: HashMap<Uid<UID_LENGTH>, Vec<Uid<UID_LENGTH>>>,
    pub(crate) chain_values: HashMap<Uid<UID_LENGTH>, HashSet<IndexedValue>>,
}

#[cfg(feature = "live_compact")]
impl<const UID_LENGTH: usize> ChainData<UID_LENGTH> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            chain_uids: HashMap::with_capacity(capacity),
            chain_values: HashMap::with_capacity(capacity),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding() {
        const BLOCK_LENGTH: usize = 3;
        const N_ADDITIONS: usize = 5;

        let mut blocks = Vec::<Block<BLOCK_LENGTH>>::new();

        // Add a value that does not fit in a single block.
        let long_indexed_value =
            IndexedValue::from(Location::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));
        blocks.extend(&long_indexed_value.to_blocks(BlockType::Addition).unwrap());

        // Try padding some small values.
        for i in 0..N_ADDITIONS {
            let indexed_value = IndexedValue::from(Location::from(vec![i as u8]));
            blocks.extend(&indexed_value.to_blocks(BlockType::Addition).unwrap());
        }

        // Assert unpadding the resulting blocks leads to the correct result.
        let res = IndexedValue::from_blocks(blocks.iter()).unwrap();
        assert_eq!(res.len(), N_ADDITIONS + 1);
        assert!(res.contains(&long_indexed_value));
        for i in 0..N_ADDITIONS {
            assert!(res.contains(&IndexedValue::from(Location::from(vec![i as u8]))));
        }

        // Try deleting some values.
        blocks.extend(&long_indexed_value.to_blocks(BlockType::Deletion).unwrap());
        for i in 1..N_ADDITIONS {
            let indexed_value = IndexedValue::from(Location::from(vec![i as u8]));
            blocks.extend(indexed_value.to_blocks(BlockType::Deletion).unwrap());
        }

        // Assert unpadding the resulting blocks leads to the correct result.
        let res = IndexedValue::from_blocks(blocks.iter()).unwrap();
        assert_eq!(res.len(), 1);
        assert!(res.contains(&IndexedValue::from(Location::from(vec![0]))));
    }
}
