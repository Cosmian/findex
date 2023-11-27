//! Defines error type and conversions for Findex.

use core::fmt::{Debug, Display};

use cosmian_crypto_core::CryptoCoreError;
use never::Never;

/// Marker trait for `Backend` errors.
pub trait BackendErrorTrait: std::error::Error {}

#[derive(Debug)]
pub enum Error<T: std::error::Error> {
    Crypto(String),
    CryptoCore(CryptoCoreError),
    Conversion(String),
    Backend(T),
    Interrupt(String),
    Filter(String),
}

impl<T: std::error::Error> Display for Error<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crypto(msg) | Self::Conversion(msg) => {
                write!(f, "crypto error: {msg}")
            }
            Self::CryptoCore(err) => write!(f, "CryptoCore error: {err}"),
            Self::Backend(msg) => write!(f, "backend error: {msg}"),
            Self::Interrupt(error) => write!(f, "user interrupt error: {error}"),
            Self::Filter(error) => write!(f, "user filter error: {error}"),
        }
    }
}

impl<T: std::error::Error> From<std::num::TryFromIntError> for Error<T> {
    fn from(e: std::num::TryFromIntError) -> Self {
        Self::Conversion(e.to_string())
    }
}

impl<T: std::error::Error> From<CryptoCoreError> for Error<T> {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptoCore(e)
    }
}

impl<T: BackendErrorTrait> From<T> for Error<T> {
    fn from(value: T) -> Self {
        Self::Backend(value)
    }
}

impl<T: std::error::Error> std::error::Error for Error<T> {}

/// Alias used to represent a Findex error that does not originate from a
/// callback.
pub type CoreError = Error<Never>;

impl<T: BackendErrorTrait> From<CoreError> for Error<T> {
    fn from(value: CoreError) -> Self {
        match value {
            CoreError::Crypto(err) => Self::Crypto(err),
            CoreError::CryptoCore(err) => Self::CryptoCore(err),
            CoreError::Conversion(err) => Self::Conversion(err),
            CoreError::Backend(_) => {
                panic!("this cannot happen because CoreError uses the `Never` type");
            }
            CoreError::Interrupt(err) => Self::Interrupt(err),
            CoreError::Filter(err) => Self::Filter(err),
        }
    }
}
