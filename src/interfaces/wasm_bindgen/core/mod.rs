//! Implements Findex traits for [`FindexUser`] and defines WASM types for
//! Findex callbacks.

#[macro_use]
mod utils;
mod traits;
mod types;

pub use types::*;

/// Implements [`FindexSearch`](crate::core::FindexSearch) and
/// [`FindexUpsert`](crate::core::FindexUpsert).
pub struct FindexUser {
    pub(crate) progress: Option<Progress>,
    pub(crate) fetch_entry: Option<Fetch>,
    pub(crate) fetch_chain: Option<Fetch>,
    pub(crate) upsert_entry: Option<Upsert>,
    pub(crate) insert_chain: Option<Insert>,
}
