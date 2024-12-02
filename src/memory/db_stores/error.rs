use core::fmt::Display;
use std::num::TryFromIntError;

#[cfg(feature = "redis-store")]
use super::redis_store::RedisStoreError;
use crate::{Address, error::Error as FindexCoreError};

macro_rules! findex_core_error {
    () => {
        FindexCoreError<Address<{ crate::ADDRESS_LENGTH }>, Box<DbStoreError>> // todo(hatem) : wrong type solve infinite size loop
    };
}
#[derive(Debug)]
pub(crate) enum DbStoreError {
    #[cfg(feature = "redis-store")]
    Redis(RedisStoreError),
    Findex(findex_core_error!()),
    IntConversion(TryFromIntError),
    Io(std::io::Error),
}

impl Display for DbStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "redis-store")]
            Self::Redis(err) => write!(f, "redis: {err}"),
            Self::Findex(err) => write!(f, "findex: {err}"),
            Self::Io(err) => write!(f, "io: {err}"),
            Self::IntConversion(err) => write!(f, "conversion: {err}"),
        }
    }
}

impl std::error::Error for DbStoreError {}

// impl DbStoreErrorTrait for DbStoreError {}

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
