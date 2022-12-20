//! Implements Findex traits for [`FindexUser`] and declare FFI types for the
//! callbacks.

#[macro_use]
mod utils;
mod callbacks;
mod traits;

pub use self::callbacks::*;

/// A pagination is performed in order to fetch the entire Entry Table. It is
/// fetched by batches of size [`NUMBER_OF_ENTRY_TABLE_LINE_IN_BATCH`].
pub const NUMBER_OF_ENTRY_TABLE_LINE_IN_BATCH: usize = 100;

/// Implements Findex traits.
pub struct FindexUser {
    pub(crate) progress: Option<ProgressCallback>,
    pub(crate) fetch_all_entry_table_uids: Option<FetchAllEntryTableUidsCallback>,
    pub(crate) fetch_entry: Option<FetchEntryTableCallback>,
    pub(crate) fetch_chain: Option<FetchChainTableCallback>,
    pub(crate) upsert_entry: Option<UpsertEntryTableCallback>,
    pub(crate) insert_chain: Option<InsertChainTableCallback>,
    pub(crate) update_lines: Option<UpdateLinesCallback>,
    pub(crate) list_removed_locations: Option<ListRemovedLocationsCallback>,
}
