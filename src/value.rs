//! Boring implementation of a typed byte-vector.

// TODO: Maybe turn all that in a macro (maybe in CryptoCore?) to reuse it for the words and maybe
// others.

use std::string::FromUtf8Error;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Value(Vec<u8>);

impl From<&[u8]> for Value {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&Value> for Vec<u8> {
    fn from(value: &Value) -> Self {
        value.0.to_vec()
    }
}

impl From<Value> for Vec<u8> {
    fn from(value: Value) -> Self {
        value.0
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self(value.as_bytes().to_vec())
    }
}

impl TryFrom<Value> for String {
    type Error = FromUtf8Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        String::from_utf8(value.0)
    }
}

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self(value.to_be_bytes().to_vec())
    }
}
