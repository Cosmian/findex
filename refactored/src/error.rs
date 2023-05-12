//! Defines error type and conversions for Findex.

use core::fmt::{Debug, Display};

use cosmian_crypto_core::CryptoCoreError;

/// Marker trait indicating an error type is used as `CallbackError`.
pub trait CallbackError {}

#[derive(Debug)]
pub enum Error<T: std::error::Error> {
    CryptoError(String),
    CryptoCoreError(CryptoCoreError),
    ConversionError(String),
    Callback(T),
}

impl<T: std::error::Error> Display for Error<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CryptoError(msg) | Self::ConversionError(msg) => {
                write!(f, "{msg}")
            }
            Self::CryptoCoreError(err) => write!(f, "{err}"),
            Self::Callback(msg) => write!(f, "{msg}"),
        }
    }
}

impl<T: std::error::Error> From<std::num::TryFromIntError> for Error<T> {
    fn from(e: std::num::TryFromIntError) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl<T: std::error::Error> From<CryptoCoreError> for Error<T> {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptoCoreError(e)
    }
}

impl<T: std::error::Error + CallbackError> From<T> for Error<T> {
    fn from(value: T) -> Self {
        Self::Callback(value)
    }
}

impl<T: std::error::Error> std::error::Error for Error<T> {}

/// Alias used to represent a Findex error that does not originate from a
/// callback.
pub type CoreError = Error<!>;

impl<T: std::error::Error + CallbackError> From<CoreError> for Error<T> {
    fn from(value: CoreError) -> Self {
        match value {
            CoreError::CryptoError(err) => Self::CryptoError(err),
            CoreError::CryptoCoreError(err) => Self::CryptoCoreError(err),
            CoreError::ConversionError(err) => Self::ConversionError(err),
            CoreError::Callback(_) => {
                panic!("this cannot happen because CoreError uses the `!` type");
            }
        }
    }
}
