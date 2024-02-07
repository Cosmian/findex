use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    hash::Hash,
    ops::{Deref, DerefMut},
};

use base64::engine::{general_purpose::STANDARD, Engine};

// This type is needed to add automatic logging (we need all argument types to
// implement `Display`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagSet<Tag: Hash + Eq + PartialEq>(HashSet<Tag>);

impl<Tag: Hash + Eq + PartialEq> Deref for TagSet<Tag> {
    type Target = HashSet<Tag>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Tag: AsRef<[u8]> + Hash + Eq + PartialEq> Display for TagSet<Tag> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "[")?;
        for tag in &self.0 {
            writeln!(f, "  {},", STANDARD.encode(tag))?;
        }
        write!(f, "]")
    }
}

impl<Tag: Hash + Eq + PartialEq> FromIterator<Tag> for TagSet<Tag> {
    fn from_iter<T: IntoIterator<Item = Tag>>(iter: T) -> Self {
        Self(HashSet::from_iter(iter))
    }
}

impl<Tag: Hash + Eq + PartialEq> IntoIterator for TagSet<Tag> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = Tag;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Tag: Hash + Eq + PartialEq> From<HashSet<Tag>> for TagSet<Tag> {
    fn from(value: HashSet<Tag>) -> Self {
        Self(value)
    }
}

impl<Tag: Hash + Eq + PartialEq> From<TagSet<Tag>> for HashSet<Tag> {
    fn from(value: TagSet<Tag>) -> Self {
        value.0
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

pub type Value<const LENGTH: usize> = [u8; LENGTH];

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Dx<Tag: Hash + Eq + PartialEq, const VALUE_LENGTH: usize>(
    HashMap<Tag, Value<VALUE_LENGTH>>,
);

impl<Tag: Hash + Eq + PartialEq, const VALUE_LENGTH: usize> Deref for Dx<Tag, VALUE_LENGTH> {
    type Target = HashMap<Tag, Value<VALUE_LENGTH>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Tag: Hash + Eq + PartialEq, const VALUE_LENGTH: usize> DerefMut for Dx<Tag, VALUE_LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<Tag: Hash + Eq + PartialEq + AsRef<[u8]>, const VALUE_LENGTH: usize> Display
    for Dx<Tag, VALUE_LENGTH>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Dictionary: {{")?;
        for (tag, value) in self.iter() {
            writeln!(
                f,
                "  '{}': {}",
                STANDARD.encode(tag),
                STANDARD.encode(value)
            )?;
        }
        writeln!(f, "}}")
    }
}

impl<Tag: Hash + Eq + PartialEq, const VALUE_LENGTH: usize> From<HashMap<Tag, Value<VALUE_LENGTH>>>
    for Dx<Tag, VALUE_LENGTH>
{
    fn from(value: HashMap<Tag, Value<VALUE_LENGTH>>) -> Self {
        Self(value)
    }
}

impl<Tag: Hash + Eq + PartialEq, const VALUE_LENGTH: usize> From<Dx<Tag, VALUE_LENGTH>>
    for HashMap<Tag, Value<VALUE_LENGTH>>
{
    fn from(value: Dx<Tag, VALUE_LENGTH>) -> Self {
        value.0
    }
}

impl<Tag: Hash + Eq + PartialEq, const VALUE_LENGTH: usize> FromIterator<(Tag, Value<VALUE_LENGTH>)>
    for Dx<Tag, VALUE_LENGTH>
{
    fn from_iter<T: IntoIterator<Item = (Tag, Value<VALUE_LENGTH>)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl<Tag: Hash + Eq + PartialEq, const VALUE_LENGTH: usize> IntoIterator for Dx<Tag, VALUE_LENGTH> {
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
