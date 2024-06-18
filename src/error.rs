use std::fmt::{Debug, Display};

use cosmian_crypto_core::CryptoCoreError;

#[derive(Debug)]
pub enum Error<Address: Debug, MemoryError: std::error::Error> {
    Parsing(String),
    Encryption(CryptoCoreError),
    Memory(MemoryError),
    Conversion(String),
    MissingValue(Address),
}

impl<Address: Debug, MemoryError: std::error::Error> Display for Error<Address, MemoryError> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parsing(e) => write!(f, "{}", e),
            _ => write!(f, "Error"),
        }
    }
}

impl<Address: Debug, MemoryError: std::error::Error> std::error::Error
    for Error<Address, MemoryError>
{
}

impl<Address: Debug, MemoryError: std::error::Error> From<MemoryError>
    for Error<Address, MemoryError>
{
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}
