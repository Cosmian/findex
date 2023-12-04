//! Structures used by the `Index` interface of `Findex`.

use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    ops::{Deref, DerefMut},
};

use cosmian_crypto_core::{reexport::rand_core::CryptoRngCore, SymmetricKey};

use crate::{IndexedValue, USER_KEY_LENGTH};

pub type UserKey = SymmetricKey<USER_KEY_LENGTH>;

/// The label is used to provide additional public information to the hash
/// algorithm when generating Entry Table UIDs.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// A [`Data`] is an arbitrary byte-string that is indexed under some keyword.
///
/// In a typical use case, it would represent a database UID and would be indexed under the
/// keywords associated to the corresponding database value.
#[must_use]
#[derive(Clone, Debug, Hash, Default, PartialEq, Eq)]
pub struct Data(Vec<u8>);

impl_byte_vector!(Data);

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Keywords(HashSet<Keyword>);

impl Deref for Keywords {
    type Target = HashSet<Keyword>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Keywords {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromIterator<&'static str> for Keywords {
    fn from_iter<T: IntoIterator<Item = &'static str>>(iter: T) -> Self {
        Self(HashSet::from_iter(iter.into_iter().map(Keyword::from)))
    }
}

impl FromIterator<Keyword> for Keywords {
    fn from_iter<T: IntoIterator<Item = Keyword>>(iter: T) -> Self {
        Self(HashSet::from_iter(iter))
    }
}

impl IntoIterator for Keywords {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = Keyword;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Display for Keywords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Keywords: [")?;
        for keyword in &self.0 {
            writeln!(f, "  {keyword},")?;
        }
        writeln!(f, "]")
    }
}

impl From<HashSet<Keyword>> for Keywords {
    fn from(set: HashSet<Keyword>) -> Self {
        Self(set)
    }
}

impl From<Keywords> for HashSet<Keyword> {
    fn from(value: Keywords) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeywordToDataMap(HashMap<Keyword, HashSet<Data>>);

impl Deref for KeywordToDataMap {
    type Target = HashMap<Keyword, HashSet<Data>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for KeywordToDataMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for KeywordToDataMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Keyword to Data map: {{")?;
        for (keyword, data) in &self.0 {
            writeln!(f, "  '{keyword}': [")?;
            for data in data {
                writeln!(f, "      '{data}',")?;
            }
            writeln!(f, "    ]")?;
        }
        write!(f, "}}")
    }
}

impl FromIterator<(Keyword, HashSet<Data>)> for KeywordToDataMap {
    fn from_iter<T: IntoIterator<Item = (Keyword, HashSet<Data>)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl IntoIterator for KeywordToDataMap {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = (Keyword, HashSet<Data>);

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl From<HashMap<Keyword, HashSet<Data>>> for KeywordToDataMap {
    fn from(map: HashMap<Keyword, HashSet<Data>>) -> Self {
        Self(map)
    }
}

impl From<KeywordToDataMap> for HashMap<Keyword, HashSet<Data>> {
    fn from(value: KeywordToDataMap) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IndexedValueToKeywordsMap(HashMap<IndexedValue<Keyword, Data>, Keywords>);

impl Deref for IndexedValueToKeywordsMap {
    type Target = HashMap<IndexedValue<Keyword, Data>, Keywords>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for IndexedValueToKeywordsMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "IndexedValue to Keyword map: {{")?;
        for (iv, keywords) in &self.0 {
            writeln!(f, "'{iv}': {keywords},")?;
        }
        write!(f, "}}")
    }
}

impl IntoIterator for IndexedValueToKeywordsMap {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = (IndexedValue<Keyword, Data>, Keywords);

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<(IndexedValue<Keyword, Data>, Keywords)> for IndexedValueToKeywordsMap {
    fn from_iter<T: IntoIterator<Item = (IndexedValue<Keyword, Data>, Keywords)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl FromIterator<(IndexedValue<Keyword, Data>, HashSet<Keyword>)> for IndexedValueToKeywordsMap {
    fn from_iter<T: IntoIterator<Item = (IndexedValue<Keyword, Data>, HashSet<Keyword>)>>(
        iter: T,
    ) -> Self {
        Self(HashMap::from_iter(
            iter.into_iter().map(|(k, v)| (k, Keywords::from(v))),
        ))
    }
}

impl From<HashMap<IndexedValue<Keyword, Data>, Keywords>> for IndexedValueToKeywordsMap {
    fn from(map: HashMap<IndexedValue<Keyword, Data>, Keywords>) -> Self {
        Self(map)
    }
}

impl From<HashMap<IndexedValue<Keyword, Data>, HashSet<Keyword>>> for IndexedValueToKeywordsMap {
    fn from(map: HashMap<IndexedValue<Keyword, Data>, HashSet<Keyword>>) -> Self {
        Self(
            map.into_iter()
                .map(|(iv, k)| (iv, Keywords::from(k)))
                .collect(),
        )
    }
}

impl<const N: usize> From<[(IndexedValue<Keyword, Data>, Keywords); N]>
    for IndexedValueToKeywordsMap
{
    fn from(value: [(IndexedValue<Keyword, Data>, Keywords); N]) -> Self {
        Self(HashMap::from(value))
    }
}
