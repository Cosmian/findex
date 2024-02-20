use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    hash::Hash,
    ops::{Deref, DerefMut},
};

use base64::engine::{general_purpose::STANDARD, Engine};

use crate::CoreError;

impl_byte_array!(Tag, 16, "Tag");

impl TryFrom<&[u8]> for Tag {
    type Error = CoreError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; Self::LENGTH]>::try_from(bytes)
            .map_err(|_| {
                Self::Error::Conversion(format!(
                    "incorrect byte length: expected {}, found {}",
                    Self::LENGTH,
                    bytes.len()
                ))
            })
            .map(Self)
    }
}

// This type is needed to add automatic logging (we need all argument types to
// implement `Display`).
#[derive(Eq, PartialEq)]
pub struct Set<Item: Hash + PartialEq + Eq>(HashSet<Item>);

impl<Item: Hash + PartialEq + Eq> Default for Set<Item> {
    fn default() -> Self {
        Self(HashSet::new())
    }
}

impl<Item: Hash + PartialEq + Eq> Deref for Set<Item> {
    type Target = HashSet<Item>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Item: Hash + PartialEq + Eq> DerefMut for Set<Item> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<Item: Hash + PartialEq + Eq + Display> Display for Set<Item> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{{")?;
        for tag in &self.0 {
            writeln!(f, "  {},", tag)?;
        }
        writeln!(f, "}}")
    }
}

impl<Item: Hash + PartialEq + Eq + Debug> Debug for Set<Item> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?}", self.0)
    }
}

impl<Item: Hash + PartialEq + Eq> FromIterator<Item> for Set<Item> {
    fn from_iter<T: IntoIterator<Item = Item>>(iter: T) -> Self {
        Self(HashSet::from_iter(iter))
    }
}

impl<Item: Hash + PartialEq + Eq> IntoIterator for Set<Item> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = Item;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Item: Hash + PartialEq + Eq> From<HashSet<Item>> for Set<Item> {
    fn from(value: HashSet<Item>) -> Self {
        Self(value)
    }
}

impl<Item: Hash + PartialEq + Eq> From<Set<Item>> for HashSet<Item> {
    fn from(value: Set<Item>) -> Self {
        value.0
    }
}

impl<Item: Hash + PartialEq + Eq + Clone> Clone for Set<Item> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Size of the token used. It is 256 bits in order to allow more than 80 bits
/// of post-quantum resistance.
const TOKEN_LENGTH: usize = 32;

impl_byte_array!(Token, TOKEN_LENGTH, "Token");

#[derive(PartialEq)]
pub struct Dx<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq, Item>(HashMap<Tag, Item>);

impl<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq, Item> Default
    for Dx<VALUE_LENGTH, Tag, Item>
{
    fn default() -> Self {
        Self(HashMap::default())
    }
}

impl<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq, Item> Deref
    for Dx<VALUE_LENGTH, Tag, Item>
{
    type Target = HashMap<Tag, Item>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq, Item> DerefMut
    for Dx<VALUE_LENGTH, Tag, Item>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq + Display, Item: Display> Display
    for Dx<VALUE_LENGTH, Tag, Item>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Dictionary: {{")?;
        for (tag, value) in self.0.iter() {
            writeln!(f, "'{tag}': {value}")?;
        }
        writeln!(f, "}}")
    }
}

impl<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq + Debug, Item: Debug> Debug
    for Dx<VALUE_LENGTH, Tag, Item>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?}", self.0)
    }
}

impl<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq + Clone, Item: Clone> Clone
    for Dx<VALUE_LENGTH, Tag, Item>
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq, Item> From<HashMap<Tag, Item>>
    for Dx<VALUE_LENGTH, Tag, Item>
{
    fn from(value: HashMap<Tag, Item>) -> Self {
        Self(value)
    }
}

impl<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq, Item> From<Dx<VALUE_LENGTH, Tag, Item>>
    for HashMap<Tag, Item>
{
    fn from(value: Dx<VALUE_LENGTH, Tag, Item>) -> Self {
        value.0
    }
}

impl<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq, Item> FromIterator<(Tag, Item)>
    for Dx<VALUE_LENGTH, Tag, Item>
{
    fn from_iter<T: IntoIterator<Item = (Tag, Item)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq, Item> IntoIterator
    for Dx<VALUE_LENGTH, Tag, Item>
{
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = <<Self as Deref>::Target as IntoIterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// We would like to use an array as ciphertext value. However, constant generics
// cannot be used in constant operations yet. This is a blocking missing feature.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Edx(HashMap<Token, Vec<u8>>);

impl Deref for Edx {
    type Target = HashMap<Token, Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Edx {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Display for Edx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Token to EncryptedValue map: {{")?;
        for (token, encrypted_value) in self.iter() {
            writeln!(
                f,
                "  '{}': {}",
		token,
                STANDARD.encode(encrypted_value)
            )?;
        }
        writeln!(f, "}}")
    }
}

impl From<HashMap<Token, Vec<u8>>> for Edx {
    fn from(value: HashMap<Token, Vec<u8>>) -> Self {
        Self(value)
    }
}

impl From<Edx> for HashMap<Token, Vec<u8>> {
    fn from(value: Edx) -> Self {
        value.0
    }
}

impl FromIterator<(Token, Vec<u8>)> for Edx {
    fn from_iter<T: IntoIterator<Item = (Token, Vec<u8>)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl IntoIterator for Edx {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = <<Self as Deref>::Target as IntoIterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
