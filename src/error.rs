use std::fmt::Display;

use cosmian_crypto_core::CryptoCoreError;

#[derive(Debug)]
pub enum Error<MemoryError: std::error::Error> {
    Parsing(String),
    Encryption(CryptoCoreError),
    Memory(MemoryError),
}

impl<MemoryError: std::error::Error> Display for Error<MemoryError> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parsing(e) => write!(f, "{}", e),
            _ => write!(f, "Error"),
        }
    }
}

impl<MemoryError: std::error::Error> std::error::Error for Error<MemoryError> {}

impl<MemoryError: std::error::Error> From<MemoryError> for Error<MemoryError> {
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}
