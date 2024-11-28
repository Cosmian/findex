use core::fmt::Display;
use std::{array::TryFromSliceError, num::TryFromIntError};

use cosmian_crypto_core::CryptoCoreError;
use cosmian_findex::{CoreError as FindexCoreError, DbStoreErrorTrait};
#[cfg(feature = "redis-store")]
use redis::RedisStoreError;

#[derive(Debug)]
pub enum DbStoreError {
    #[cfg(feature = "redis-store")]
    Redis(RedisStoreError),
    MissingCallback(String),
    Findex(FindexCoreError),
    CryptoCore(CryptoCoreError),
    Serialization(String),
    IntConversion(TryFromIntError),
    SliceConversion(TryFromSliceError),
    Other(String),
    Io(std::io::Error),
}

impl Display for DbStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "redis-store")]
            Self::Redis(err) => write!(f, "redis: {err}"),
            Self::MissingCallback(err) => write!(f, "unknown callback: {err}"),
            Self::CryptoCore(err) => write!(f, "crypto_core: {err}"),
            Self::Findex(err) => write!(f, "findex: {err}"),
            Self::Io(err) => write!(f, "io: {err}"),
            Self::Serialization(err) => write!(f, "serialization: {err}"),
            Self::IntConversion(err) => write!(f, "conversion: {err}"),
            Self::SliceConversion(err) => write!(f, "conversion: {err}"),
            Self::Other(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for DbStoreError {}

impl DbStoreErrorTrait for DbStoreError {}

#[cfg(feature = "redis-store")]
impl From<RedisStoreError> for DbStoreError {
    fn from(e: RedisStoreError) -> Self {
        Self::Redis(e)
    }
}

impl From<TryFromIntError> for DbStoreError {
    fn from(e: TryFromIntError) -> Self {
        Self::IntConversion(e)
    }
}

impl From<CryptoCoreError> for DbStoreError {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptoCore(e)
    }
}

impl From<FindexCoreError> for DbStoreError {
    fn from(e: FindexCoreError) -> Self {
        Self::Findex(e)
    }
}

impl From<std::io::Error> for DbStoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
