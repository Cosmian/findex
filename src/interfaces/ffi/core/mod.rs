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

#[repr(i32)]
#[derive(Debug)]
/// Callbacks return error codes, right now only 0 and 1 are specified.
/// Other error codes will be forwarded to the client as a response to
/// the main call error code so that the client can report some custom
/// callbacks errors (for example the Flutter lib is using 42 to report
/// an exception during a callback, save this exception and re-report this
/// exception at the end of the main call if the response is 42).
pub enum ErrorCode {
    Success = 0,

    /// <https://github.com/Cosmian/findex/issues/14>
    /// We use 1 here because we used to always retry in case of non-zero error
    /// code. We may want to change this in future major release (reserve 1
    /// for error and specify another error code for asking for a bigger
    /// buffer).
    BufferTooSmall = 1,
}

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
