//! Defines error type and conversions for Findex.

use std::fmt::Display;

use cosmian_crypto_core::CryptoCoreError;
use js_sys::{JsString, Object};
use wasm_bindgen::JsCast;
#[cfg(feature = "wasm_bindgen")]
use wasm_bindgen::JsValue;

#[derive(Debug)]
pub enum FindexErr {
    CryptoError(String),
    CryptoCoreError(CryptoCoreError),
    ConversionError(String),
    Other(String),

    // Findex implementation for FFI
    #[cfg(feature = "interfaces")]
    CallBack(String),

    /// Findex implementation with sqlite
    #[cfg(feature = "sqlite")]
    RusqliteError(rusqlite::Error),
    #[cfg(feature = "sqlite")]
    IoError(std::io::Error),
    #[cfg(feature = "sqlite")]
    SerdeJsonError(serde_json::Error),

    #[cfg(feature = "wasm_bindgen")]
    JsError(JsValue),
}

impl Display for FindexErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CryptoError(msg) | Self::ConversionError(msg) | Self::Other(msg) => {
                write!(f, "{msg}")
            }
            Self::CryptoCoreError(err) => write!(f, "{err}"),

            #[cfg(feature = "sqlite")]
            Self::RusqliteError(err) => write!(f, "{err}"),
            #[cfg(feature = "sqlite")]
            Self::IoError(err) => write!(f, "{err}"),
            #[cfg(feature = "sqlite")]
            Self::SerdeJsonError(err) => write!(f, "{err}"),

            #[cfg(feature = "interfaces")]
            Self::CallBack(msg) => write!(f, "{msg}"),

            #[cfg(feature = "wasm_bindgen")]
            Self::JsError(value) => match value.dyn_ref::<JsString>() {
                Some(string) => write!(f, "{string}"),
                None => match value.dyn_ref::<Object>() {
                    // Object in Err is often an `Error` with a simple toString()
                    Some(object) => write!(f, "{}", object.to_string()),
                    // If it's neither a string, nor an object, print the debug JsValue.
                    None => write!(f, "{value:?}"),
                },
            },
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
        Self::JsError(e)
    }
}

#[cfg(feature = "python")]
impl From<FindexErr> for pyo3::PyErr {
    fn from(e: FindexErr) -> Self {
        pyo3::exceptions::PyException::new_err(format!("{e}"))
    }
}
