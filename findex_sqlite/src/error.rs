use core::fmt::Display;
use std::num::TryFromIntError;

use cosmian_crypto_core::CryptoCoreError;
use cosmian_findex::{CallbackError, CoreError as FindexCoreError, Error as FindexError};

#[derive(Debug)]
pub enum Error {
    RusqliteError(rusqlite::Error),
    IoError(std::io::Error),
    SerdeJsonError(serde_json::Error),
    SerializationError(String),
    ConversionError(TryFromIntError),
    Other(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RusqliteError(err) => write!(f, "{err}"),
            Self::IoError(err) => write!(f, "{err}"),
            Self::SerdeJsonError(err) => write!(f, "{err}"),
            Self::SerializationError(err) => write!(f, "{err}"),
            Self::ConversionError(err) => write!(f, "{err}"),
            Self::Other(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Error {}
impl CallbackError for Error {}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::RusqliteError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeJsonError(e)
    }
}

impl From<TryFromIntError> for Error {
    fn from(e: TryFromIntError) -> Self {
        Self::ConversionError(e)
    }
}

impl From<CryptoCoreError> for Error {
    fn from(e: CryptoCoreError) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<FindexCoreError> for Error {
    fn from(e: FindexCoreError) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<FindexError<Error>> for Error {
    fn from(value: FindexError<Error>) -> Self {
        if let FindexError::Callback(error) = value {
            error
        } else {
            Self::Other(value.to_string())
        }
    }
}
