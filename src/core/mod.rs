//! Implements the core functionalities of Findex.
//!
//! These functionalities are exported under the form of three traits:
//!
//! 1- [`FindexSearch`](FindexSearch) allows searching for keywords;
//!
//! 2- [`FindexUpsert`](FindexUpsert) allows indexing new values with given
//! keywords;
//!
//! 3- [`FindexCompact`](FindexCompact) allows compacting the indexes;
//
// TODO (TBZ): replace hash maps by vectors wherever possible.

const ENTRY_TABLE_KEY_DERIVATION_INFO: &[u8] = b"Entry Table key derivation info.";
const CHAIN_TABLE_KEY_DERIVATION_INFO: &[u8] = b"Chain Table key derivation info.";

// Macros should be defined first in order to be available for other modules
#[macro_use]
pub mod macros;

mod callbacks;
mod chain_table;
mod compact;
mod entry_table;
mod keys;
mod search;
mod structs;
mod upsert;

pub use callbacks::FindexCallbacks;
pub use compact::FindexCompact;
pub use keys::KeyingMaterial;
pub use search::FindexSearch;
pub use structs::{EncryptedTable, IndexedValue, Keyword, Label, Location, Uid, UpsertData};
pub use upsert::FindexUpsert;
