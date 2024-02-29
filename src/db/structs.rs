use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    ops::{Deref, DerefMut},
};

use base64::{engine::general_purpose::STANDARD, Engine};

/// Size of the token used. It is 256 bits in order to allow more than 80 bits
/// of post-quantum resistance.
const TOKEN_LENGTH: usize = 32;

impl_byte_array!(Token, TOKEN_LENGTH, "Token");

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
            writeln!(f, "  '{}': {}", token, STANDARD.encode(encrypted_value))?;
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
