use std::fmt::{Debug, Display};

use cosmian_crypto_core::CryptoCoreError;

#[derive(Debug)]
pub enum Error<Address> {
    Parsing(String),
    Memory(String),
    Conversion(String),
    MissingValue(Address, usize),
    CorruptedMemoryCache,
    Other(String),
}

impl<Address: Debug> Display for Error<Address> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<Address: Debug> std::error::Error for Error<Address> {}

impl<Address> From<CryptoCoreError> for Error<Address> {
    fn from(value: CryptoCoreError) -> Self {
        Self::Other(value.to_string())
    }
}
