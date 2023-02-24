//! Defines error type and conversions for Findex.

use std::fmt::Display;

use base64::DecodeError;
use cosmian_crypto_core::CryptoCoreError;

#[derive(Debug)]
pub enum FindexErr {
    CryptoError(String),
    CryptoCoreError(CryptoCoreError),
    ConversionError(String),
    Other(String),

    // Findex implementation for FFI
    CallBack(String),
    #[cfg(feature = "interfaces")]
    CallbackErrorCode {
        name: &'static str,
        code: i32,
    },

    DecodeError(DecodeError),
}

impl Display for FindexErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CryptoError(msg) | Self::ConversionError(msg) | Self::Other(msg) => {
                write!(f, "{msg}")
            }
            Self::CryptoCoreError(err) => write!(f, "{err}"),

            Self::DecodeError(err) => write!(f, "{err}"),

            Self::CallBack(msg) => write!(f, "{msg}"),
            #[cfg(feature = "interfaces")]
            Self::CallbackErrorCode { name, code } => {
                write!(f, "callback '{name}' returned an error code: {code}")
            }
        }
    }
}

impl From<std::num::TryFromIntError> for FindexErr {
    fn from(e: std::num::TryFromIntError) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<CryptoCoreError> for FindexErr {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptoCoreError(e)
    }
}

impl From<DecodeError> for FindexErr {
    fn from(e: DecodeError) -> Self {
        Self::DecodeError(e)
    }
}
