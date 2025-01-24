//! Boring implementation of a typed byte-vector.

// TODO: Maybe turn all that in a macro (maybe in CryptoCore?) to reuse it for the words and maybe
// others.

use std::string::FromUtf8Error;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Value(Vec<u8>);

impl AsRef<[u8]> for Value {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

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
        value.0.clone()
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
        Self::from_utf8(value.0)
    }
}

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self(value.to_be_bytes().to_vec())
    }
}

impl From<i32> for Value {
    fn from(num: i32) -> Self {
        let mut bytes = num.to_be_bytes().to_vec();
        // Remove leading zeros
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes.remove(0);
        }
        Value(bytes)
    }
}
