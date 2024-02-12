use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
    hash::Hash,
    ops::{Deref, DerefMut},
};

use base64::engine::{general_purpose::STANDARD, Engine};

// This type is needed to add automatic logging (we need all argument types to
// implement `Display`).
#[derive(Eq, PartialEq)]
pub struct TagSet<Tag: Hash + PartialEq + Eq>(HashSet<Tag>);

impl<Tag: Hash + PartialEq + Eq> Deref for TagSet<Tag> {
    type Target = HashSet<Tag>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<Tag: Hash + PartialEq + Eq + Display> Display for TagSet<Tag> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[")?;
        for tag in &self.0 {
            writeln!(f, "  {},", tag)?;
        }
        write!(f, "]")
    }
}

impl<Tag: Hash + PartialEq + Eq + Debug> Debug for TagSet<Tag> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{self:?}")
    }
}

impl<Tag: Hash + PartialEq + Eq> FromIterator<Tag> for TagSet<Tag> {
    fn from_iter<T: IntoIterator<Item = Tag>>(iter: T) -> Self {
        Self(HashSet::from_iter(iter))
    }
}

impl<Tag: Hash + PartialEq + Eq> IntoIterator for TagSet<Tag> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = Tag;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Tag: Hash + PartialEq + Eq> From<HashSet<Tag>> for TagSet<Tag> {
    fn from(value: HashSet<Tag>) -> Self {
        Self(value)
    }
}

impl<Tag: Hash + PartialEq + Eq> From<TagSet<Tag>> for HashSet<Tag> {
    fn from(value: TagSet<Tag>) -> Self {
        value.0
    }
}

impl<Tag: Hash + PartialEq + Eq + Clone> Clone for TagSet<Tag> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Size of the token used. It is 256 bits in order to allow more than 80 bits
/// of post-quantum resistance.
pub const TOKEN_LENGTH: usize = 32;

pub type Token = [u8; TOKEN_LENGTH];

// This type is needed to add automatic logging (we need all argument types to
// implement `Display`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenSet(pub HashSet<Token>);

impl Deref for TokenSet {
    type Target = HashSet<Token>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[")?;
        for token in &self.0 {
            writeln!(f, "  {},", STANDARD.encode(token))?;
        }
        write!(f, "]")
    }
}

impl FromIterator<Token> for TokenSet {
    fn from_iter<T: IntoIterator<Item = Token>>(iter: T) -> Self {
        Self(HashSet::from_iter(iter))
    }
}

impl IntoIterator for TokenSet {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = Token;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl From<HashSet<Token>> for TokenSet {
    fn from(value: HashSet<Token>) -> Self {
        Self(value)
    }
}

impl From<TokenSet> for HashSet<Token> {
    fn from(value: TokenSet) -> Self {
        value.0
    }
}

#[derive(Default, PartialEq)]
pub struct Dx<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq, Item>(HashMap<Tag, Item>);

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
        write!(f, "Dictionary: {{")?;
        for (tag, value) in self.iter() {
            writeln!(f, "  '{}': {}", tag, value)?;
        }
        writeln!(f, "}}")
    }
}

impl<const VALUE_LENGTH: usize, Tag: Hash + PartialEq + Eq + Debug, Item: Debug> Debug
    for Dx<VALUE_LENGTH, Tag, Item>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{self:?}")
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
        write!(f, "Token to EncryptedValue map: {{")?;
        for (token, encrypted_value) in self.iter() {
            writeln!(
                f,
                "  '{}': {}",
                STANDARD.encode(token),
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
