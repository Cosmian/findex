//! Defines error type and conversions for Findex.

use cosmian_crypto_core::CryptoCoreError;
use thiserror::Error;
#[cfg(feature = "wasm_bindgen")]
use wasm_bindgen::JsValue;

#[derive(Error, Debug)]
pub enum FindexErr {
    #[error("{0}")]
    CryptoError(String),
    #[error("{0}")]
    ConversionError(String),
    #[error("{0}")]
    Other(String),

    // Findex implementation for FFI
    #[cfg(feature = "interfaces")]
    #[error("Callback failed: {0}")]
    CallBack(String),

    /// Findex implementation with sqlite
    #[cfg(feature = "sqlite")]
    #[error(transparent)]
    RusqliteError(#[from] rusqlite::Error),
    #[cfg(feature = "sqlite")]
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[cfg(feature = "sqlite")]
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
}

impl From<std::num::TryFromIntError> for FindexErr {
    fn from(e: std::num::TryFromIntError) -> Self {
        Self::ConversionError(e.to_string())
    }
}

impl From<CryptoCoreError> for FindexErr {
    fn from(e: CryptoCoreError) -> Self {
        Self::CryptoError(e.to_string())
    }
}

#[cfg(feature = "ffi")]
impl From<std::ffi::NulError> for FindexErr {
    fn from(e: std::ffi::NulError) -> Self {
        Self::Other(format!("FFI error: {e}"))
    }
}

#[cfg(feature = "wasm_bindgen")]
impl From<FindexErr> for JsValue {
    fn from(e: FindexErr) -> Self {
        Self::from_str(&e.to_string())
    }
}

#[cfg(feature = "wasm_bindgen")]
impl From<JsValue> for FindexErr {
    fn from(e: JsValue) -> Self {
        Self::Other(format!("{e:?}"))
    }
}

#[cfg(feature = "python")]
impl From<FindexErr> for pyo3::PyErr {
    fn from(e: FindexErr) -> Self {
        pyo3::exceptions::PyException::new_err(format!("{e}"))
    }
}
