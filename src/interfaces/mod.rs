//! Defines Findex interfaces for other languages.

pub mod generic_parameters;

#[cfg(feature = "serde")]
pub mod ser_de;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "python")]
pub mod pyo3;

#[cfg(feature = "wasm_bindgen")]
pub mod wasm_bindgen;

// This module is public because it is used for benchmarks.
#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(test)]
mod tests;
