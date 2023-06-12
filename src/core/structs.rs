//! This module defines all useful structures used by Findex.

use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    ops::{Deref, DerefMut},
    vec::Vec,
};

use cosmian_crypto_core::{
    bytes_ser_de::{to_leb128_len, Deserializer, Serializable, Serializer},
    reexport::rand_core::CryptoRngCore,
};
use sha3::{Digest, Sha3_256};

use crate::error::FindexErr;

/// The labels are used to provide additional public information to the hash
/// algorithm when generating Entry Table UIDs.
//
// TODO (TBZ): Should the label size be at least 32-bytes?
#[must_use]
#[derive(Clone)]
pub struct Label(Vec<u8>);

impl Label {
    /// Generates a new random label of 32 bytes.
    ///
    /// - `rng` : random number generator
    #[inline]
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = vec![0; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl_byte_vector!(Label);

/// A [`Keyword`] is a byte vector used to index other values.
#[must_use]
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Keyword(Vec<u8>);

impl_byte_vector!(Keyword);

impl Keyword {
    /// Number of bytes used to hash keywords.
    pub const HASH_LENGTH: usize = 32;

    /// Hash this keyword using SHA3-256.
    #[must_use]
    #[inline]
    pub fn hash(&self) -> [u8; Self::HASH_LENGTH] {
        let mut hasher = Sha3_256::default();
        hasher.update(self);
        let mut bytes = [0; Self::HASH_LENGTH];
        for (i, byte) in hasher.finalize().into_iter().enumerate() {
            bytes[i] = byte;
        }
        bytes
    }

    /// Converts this `Keyword` into an UTF-8 `String`.
    pub fn try_into_string(self) -> Result<String, FindexErr> {
        String::from_utf8(self.0).map_err(|e| {
            FindexErr::ConversionError(format!("Could not convert keyword into `String`: {e:?}"))
        })
    }
}

/// A `Block` defines a fixed-size block of bytes.
///
/// It is used to store variable length values in the Chain Table. This pads
/// lines to an equal size and avoids leaking information.
///
/// A value can be represented by several blocks. The first blocks representing
/// a value are full, i.e. no padding is necessary. The first byte is set to
/// `LENGTH`. The last block representing a value may not be full. It is
/// padded with 0s. The first byte is used to write the size of the data stored
/// in this block.
///
/// +-------------------------+--------------------------+
/// |        1 byte           | `BLOCK_LENGTH` - 1 bytes |
/// +-------------------------+--------------------------+
/// |         `LENGTH`        |                          |
/// |            or           |       padded data        |
/// | number of bytes written |                          |
/// +-------------------------+--------------------------+
///
/// The corollary is that the size of a block shall not be greater than 255
/// (`u8::MAX`). This is enough in practice because bigger blocks imply more
/// wasted space for small values (a small value would be padded to `LENGTH -
/// 1`).
#[must_use]
#[derive(Hash, PartialEq, Eq, Clone)]
pub struct Block<const LENGTH: usize>(pub(crate) [u8; LENGTH]);

impl_byte_array!(Block);

impl<const LENGTH: usize> Block<LENGTH> {
    /// Creates a new `Block` from the given bytes. Terminating blocks are
    /// prepended with the number of bytes written and padded with 0s.
    /// Non-terminating blocks are prepended with `LENGTH`.
    ///
    /// - `bytes`           : bytes to store in the block
    /// - `is_terminating`  : true if the block is the last block of a value
    pub fn new(bytes: &[u8], is_terminating: bool) -> Result<Self, FindexErr> {
        if LENGTH > u8::MAX as usize {
            return Err(FindexErr::CryptoError(format!(
                "Blocks cannot be of size {LENGTH}"
            )));
        }
        // The first byte of a block is used to write the size of the data stored inside
        // this block.
        if bytes.len() > LENGTH - 1 {
            return Err(FindexErr::CryptoError(format!(
                "Cannot create a block holding more than {} block",
                LENGTH - 1
            )));
        }
        // The default pads the entire block with 0s.
        let mut block = Self::default();
        if is_terminating {
            block[0] = bytes.len() as u8;
        } else {
            // No block can contain `LENGTH` bytes.
            block[0] = LENGTH as u8;
        }
        for (i, b) in bytes.iter().enumerate() {
            block[i + 1] = *b;
        }
        Ok(block)
    }

    /// Unpads the byte vectors contained in the given list of `Block`.
    ///
    /// - `blocks`  : list of blocks to unpad
    pub fn unpad(blocks: &[Self]) -> Result<Vec<Vec<u8>>, FindexErr> {
        let mut blocks = blocks;
        let mut res = Vec::new();
        while !blocks.is_empty() {
            // At least `LENGTH - 1` bytes will be read
            let mut bytes = Vec::with_capacity(LENGTH - 1);
            while blocks.len() > 1 && blocks[0][0] == LENGTH as u8 {
                bytes.extend_from_slice(&blocks[0][1..]);
                blocks = &blocks[1..];
            }
            let length = blocks[0][0] as usize;
            if length == LENGTH {
                return Err(FindexErr::CryptoError(
                    "Last block given is a non-terminating block.".to_string(),
                ));
            }
            bytes.extend_from_slice(&blocks[0][1..=length]);
            blocks = &blocks[1..];
            res.push(bytes);
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
    pub fn pad(mut bytes: &[u8]) -> Result<Vec<Self>, FindexErr> {
        // Number of blocks needed.
        let mut partition_size = bytes.len() / (LENGTH - 1);
        if bytes.len() % (LENGTH - 1) != 0 {
            partition_size += 1;
        }

        let mut blocks = Vec::with_capacity(partition_size);
        while bytes.len() > LENGTH - 1 {
            // this is a non-terminating block
            blocks.push(Self::new(&bytes[..LENGTH - 1], false)?);
            bytes = &bytes[LENGTH - 1..];
        }
        blocks.push(Self::new(bytes, true)?);

        Ok(blocks)
    }
}

impl<const BLOCK_LENGTH: usize> Default for Block<BLOCK_LENGTH> {
    fn default() -> Self {
        Self([0; BLOCK_LENGTH])
    }
}

/// A [`Location`] is a vector of bytes describing how to find some data indexed
/// by a [`Keyword`]. It may be a database UID, physical location coordinates of
/// a resources, an URL etc.
#[must_use]
#[derive(Hash, Default, PartialEq, Eq, Clone)]
pub struct Location(Vec<u8>);

impl_byte_vector!(Location);

/// The value indexed by a [`Keyword`]. It can be either a [`Location`] or
/// another [`Keyword`] in case the searched [`Keyword`] was a tree node.
///
/// When serialized, it is prefixed by `b'l'` if it is a [`Location`] and by
/// `b'w'` if it is a [`Keyword`].
#[must_use]
#[derive(Hash, PartialEq, Eq, Clone, Debug)]
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
    #[inline]
    #[must_use]
    pub const fn is_location(&self) -> bool {
        matches!(self, Self::Location(_))
    }

    /// Returns the underlying [`Location`] if the [`IndexedValue`] is a
    /// [`Location`].
    #[inline]
    #[must_use]
    pub const fn get_location(&self) -> Option<&Location> {
        match &self {
            Self::Location(l) => Some(l),
            Self::NextKeyword(_) => None,
        }
    }

    /// Returns `true` if the [`IndexedValue`] is a [`Keyword`].
    #[inline]
    #[must_use]
    pub const fn is_keyword(&self) -> bool {
        matches!(self, Self::NextKeyword(_))
    }

    /// Returns the underlying [`Keyword`] if the [`IndexedValue`] is a
    /// [`Keyword`].
    #[inline]
    #[must_use]
    pub const fn get_keyword(&self) -> Option<&Keyword> {
        match &self {
            Self::NextKeyword(keyword) => Some(keyword),
            Self::Location(_) => None,
        }
    }
}

impl Default for IndexedValue {
    #[inline]
    fn default() -> Self {
        Self::Location(Location::default())
    }
}

/// The reverse implementation of `to_vec()` for [`IndexedValue`].
impl TryFrom<&[u8]> for IndexedValue {
    type Error = FindexErr;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 2 {
            return Err(FindexErr::ConversionError(
                "Invalid Indexed Value: too short".to_string(),
            ));
        }
        match value[0] {
            b'l' => Ok(Self::Location(Location::from(&value[1..]))),
            b'w' => Ok(Self::NextKeyword(Keyword::from(&value[1..]))),
            x => Err(FindexErr::ConversionError(format!(
                "Invalid Indexed Value starting with {x:?}"
            ))),
        }
    }
}

impl From<Location> for IndexedValue {
    #[inline]
    fn from(value: Location) -> Self {
        Self::Location(value)
    }
}

impl From<Keyword> for IndexedValue {
    #[inline]
    fn from(value: Keyword) -> Self {
        Self::NextKeyword(value)
    }
}

impl Serializable for IndexedValue {
    type Error = FindexErr;

    #[inline]
    fn length(&self) -> usize {
        let length = 1 + match self {
            Self::Location(l) => l.len(),
            Self::NextKeyword(k) => k.len(),
        };
        to_leb128_len(length) + length
    }

    #[inline]
    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        ser.write_vec(&self.to_vec()).map_err(Self::Error::from)
    }

    #[inline]
    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        Self::try_from(de.read_vec()?.as_slice())
    }

    #[inline]
    fn try_to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
        // don't call `write()` to avoir writing size
        Ok(self.to_vec())
    }

    #[inline]
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        // don't call `read()` since there is no leading size
        Self::try_from(bytes)
    }
}

/// Index tables UID type.
#[must_use]
#[derive(Clone, PartialEq, Eq, Hash)]
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

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const UID_LENGTH: usize> DerefMut for EncryptedTable<UID_LENGTH> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const UID_LENGTH: usize> From<EncryptedTable<UID_LENGTH>>
    for HashMap<Uid<UID_LENGTH>, Vec<u8>>
{
    #[inline]
    fn from(encrypted_table: EncryptedTable<UID_LENGTH>) -> Self {
        encrypted_table.0
    }
}

impl<const UID_LENGTH: usize> From<<Self as Deref>::Target> for EncryptedTable<UID_LENGTH> {
    #[inline]
    fn from(hashmap: <Self as Deref>::Target) -> Self {
        Self(hashmap)
    }
}

impl<const UID_LENGTH: usize> IntoIterator for EncryptedTable<UID_LENGTH> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = (Uid<UID_LENGTH>, Vec<u8>);

    #[inline]
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
    type Error = FindexErr;

    #[inline]
    fn length(&self) -> usize {
        let mut length = UID_LENGTH * self.len();
        for value in self.values() {
            length += value.len();
        }
        length
    }

    #[inline]
    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = 0;
        n += ser.write_u64(self.0.len() as u64)?;
        for (uid, value) in &self.0 {
            n += ser.write_array(uid)?;
            n += ser.write_vec(value)?;
        }
        Ok(n)
    }

    #[inline]
    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let length = <usize>::try_from(de.read_u64()?)?;
        let mut items = HashMap::with_capacity(length);
        for _ in 0..length {
            let key = Uid::from(de.read_array()?);
            let value = de.read_vec()?;
            items.insert(key, value);
        }
        Ok(Self(items))
    }
}

impl<const UID_LENGTH: usize> Display for EncryptedTable<UID_LENGTH> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = String::new();
        for (uid, value) in self.0.clone() {
            output = format!(
                "uid: {:?}, value: {:?}, {}",
                base64::encode(uid),
                base64::encode(value),
                output,
            );
        }
        write!(f, "{output}")
    }
}

impl<const UID_LENGTH: usize> Display for EncryptedMultiTable<UID_LENGTH> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = String::new();
        for (uid, values) in self.0.clone() {
            let mut values_formatted = String::new();
            for value in values {
                values_formatted =
                    format!("{}, value: {:?}", values_formatted, base64::encode(value));
            }
            output = format!(
                "uid: {:?}, values: {:?}, {}",
                base64::encode(uid),
                base64::encode(values_formatted),
                output,
            );
        }
        write!(f, "{output}")
    }
}

#[derive(Default, Debug)]
pub struct EncryptedMultiTable<const UID_LENGTH: usize>(HashMap<Uid<UID_LENGTH>, Vec<Vec<u8>>>);

impl<const UID_LENGTH: usize> EncryptedMultiTable<UID_LENGTH> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(HashMap::with_capacity(capacity))
    }

    pub fn to_encrypted_table(
        self,
        debug: &'static str,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let mut table = EncryptedTable::with_capacity(self.len());

        for (uid, mut values) in self.0 {
            if let Some(value) = values.pop() {
                if !values.is_empty() {
                    return Err(FindexErr::CallBack(format!(
                        "In {debug}, UID '{}' is associated with multiple values.",
                        hex::encode(uid)
                    )));
                }

                table.insert(uid, value);
            } else {
                return Err(FindexErr::CallBack(format!(
                    "In {debug}, UID '{}' is associated with no values.",
                    hex::encode(uid)
                )));
            }
        }

        Ok(table)
    }
}

impl<const UID_LENGTH: usize> Deref for EncryptedMultiTable<UID_LENGTH> {
    type Target = HashMap<Uid<UID_LENGTH>, Vec<Vec<u8>>>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const UID_LENGTH: usize> From<<Self as Deref>::Target> for EncryptedMultiTable<UID_LENGTH> {
    #[inline]
    fn from(hashmap: <Self as Deref>::Target) -> Self {
        Self(hashmap)
    }
}

impl<const UID_LENGTH: usize> DerefMut for EncryptedMultiTable<UID_LENGTH> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const UID_LENGTH: usize> FromIterator<(Uid<UID_LENGTH>, Vec<Vec<u8>>)>
    for EncryptedMultiTable<UID_LENGTH>
{
    fn from_iter<T: IntoIterator<Item = (Uid<UID_LENGTH>, Vec<Vec<u8>>)>>(iter: T) -> Self {
        let hashmap = iter.into_iter().collect();
        Self(hashmap)
    }
}

impl<const UID_LENGTH: usize> Serializable for EncryptedMultiTable<UID_LENGTH> {
    type Error = FindexErr;

    #[inline]
    fn length(&self) -> usize {
        let mut length = UID_LENGTH * self.len();
        for value in self.values() {
            length += value.len();
        }
        length
    }

    #[inline]
    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = 0;
        n += ser.write_u64(self.0.len() as u64)?;
        for (uid, values) in &self.0 {
            for value in values {
                n += ser.write_array(uid)?;
                n += ser.write_vec(value)?;
            }
        }
        Ok(n)
    }

    #[inline]
    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let length = <usize>::try_from(de.read_u64()?)?;
        let mut items: HashMap<_, Vec<Vec<u8>>> = HashMap::with_capacity(length);
        for _ in 0..length {
            let key = Uid::from(de.read_array()?);
            let value = de.read_vec()?;
            items.entry(key).or_default().push(value);
        }
        Ok(Self(items))
    }
}

/// Data format used for upsert operations. It contains for each UID upserted
/// the old value (optiona) and the new value:
///
/// UID <-> (`OLD_VALUE`, `NEW_VALUE`)
#[must_use]
#[derive(Debug)]
pub struct UpsertData<const UID_LENGTH: usize>(
    HashMap<Uid<UID_LENGTH>, (Option<Vec<u8>>, Vec<u8>)>,
);

impl<const UID_LENGTH: usize> UpsertData<UID_LENGTH> {
    /// Build the upsert data from the old and new table.
    ///
    /// - `old_table`   : previous state of the table
    /// - `new_table`   : new state of the table
    #[inline]
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

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<const UID_LENGTH: usize> Serializable for UpsertData<UID_LENGTH> {
    type Error = FindexErr;

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
        let mut n = ser.write_u64(self.len() as u64)?;
        for (uid, (old_value, new_value)) in self.iter() {
            n += ser.write(uid)?;
            n += ser.write_vec(old_value.as_ref().unwrap_or(&empty_vec))?;
            n += ser.write_vec(new_value)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let length = de.read_u64()? as usize;
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
    use crate::core::structs::Block;

    #[test]
    fn test_padding() {
        const BLOCK_LENGTH: usize = 3;
        // Pad vector with remaining bytes.
        let bytes = vec![1, 2, 3, 4, 5];
        let blocks = Block::<BLOCK_LENGTH>::pad(&bytes).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(
            blocks,
            vec![
                Block::from([3, 1, 2]),
                Block::from([3, 3, 4]),
                Block([1, 5, 0])
            ]
        );

        let res = Block::<BLOCK_LENGTH>::unpad(&blocks).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0], bytes);

        // Pad vector without remaining byte.
        let bytes = vec![1, 2, 3, 4];
        let blocks = Block::<BLOCK_LENGTH>::pad(&bytes).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(
            blocks,
            vec![Block::from([3, 1, 2]), Block::from([2, 3, 4]),]
        );

        let res = Block::<BLOCK_LENGTH>::unpad(&blocks).unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0], bytes);

        // Pad vector in one big block
        const BLOCK_LENGTH_2: usize = 32;
        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut blocks = Block::<BLOCK_LENGTH_2>::pad(&bytes).unwrap();
        assert_eq!(blocks.len(), 1);
        // Append another big block containing the same vector.
        blocks.push(blocks[0].clone());
        let res = Block::<BLOCK_LENGTH_2>::unpad(&blocks).unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0], bytes);
        assert_eq!(res[1], bytes);
    }
}
