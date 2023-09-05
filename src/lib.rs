//! Findex allows for searching an encrypted data base. It is based on two
//! tables, namely the Entry Table and the Chain Table.
//!
//! The source code is structured as follows:
//! - the `core` module contains all the cryptographic APIs;
//! - the `interfaces` module contains interfaces with other languages.

// Rule MEM-FORGET (<https://anssi-fr.github.io/rust-guide/05_memory.html>):
// > In a secure Rust development, the forget function of std::mem (core::mem)
// must not be used.
#![deny(clippy::mem_forget)]
#![allow(incomplete_features)]

const ENTRY_TABLE_KEY_DERIVATION_INFO: &[u8] = b"Entry Table key derivation info.";
const CHAIN_TABLE_KEY_DERIVATION_INFO: &[u8] = b"Chain Table key derivation info.";

// Macros should be defined first in order to be available for other modules
#[macro_use]
pub mod macros;

mod callbacks;
mod chain_table;
mod compact;
mod entry_table;
mod error;
mod keys;
mod search;
mod structs;
mod upsert;

pub mod parameters;

#[cfg(feature = "in_memory")]
pub mod in_memory_example;

pub use callbacks::{FetchChains, FindexCallbacks};
pub use compact::FindexCompact;
pub use error::{CallbackError, CoreError, Error};
pub use keys::KeyingMaterial;
pub use search::FindexSearch;
pub use structs::{
    EncryptedMultiTable, EncryptedTable, IndexedValue, Keyword, Label, Location, Uid, Uids,
    UpsertData,
};
pub use upsert::FindexUpsert;
