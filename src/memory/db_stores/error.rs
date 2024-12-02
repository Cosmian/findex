use core::fmt::Display;
use std::num::TryFromIntError;

use cosmian_crypto_core::CryptoCoreError;

#[cfg(feature = "redis-mem")]
use super::redis_store::RedisStoreError;
use crate::{Address, error::Error as FindexCoreError};

macro_rules! findex_core_error {
    () => {
        FindexCoreError<Address<{ crate::ADDRESS_LENGTH }>, Box<DbStoreError>> // todo(hatem) : wrong type solve infinite size loop
    };
}
#[derive(Debug)]
pub(crate) enum DbStoreError {
    #[cfg(feature = "redis-mem")]
    Redis(RedisStoreError),
    Findex(findex_core_error!()),
    CryptoCore(CryptoCoreError),
    IntConversion(TryFromIntError),
    Io(std::io::Error),
}

impl Display for DbStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "redis-mem")]
            Self::Redis(err) => write!(f, "redis: {err}"),
            Self::CryptoCore(err) => write!(f, "crypto_core: {err}"),
            Self::Findex(err) => write!(f, "findex: {err}"),
            Self::Io(err) => write!(f, "io: {err}"),
            Self::IntConversion(err) => write!(f, "conversion: {err}"),
        }
    }
}

impl std::error::Error for DbStoreError {}

// impl DbStoreErrorTrait for DbStoreError {}

#[cfg(feature = "redis-mem")]
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

impl From<findex_core_error!()> for DbStoreError {
    fn from(e: findex_core_error!()) -> Self {
        Self::Findex(e)
    }
}

impl From<std::io::Error> for DbStoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
