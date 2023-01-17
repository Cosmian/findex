//! Defines the FFI types for the callbacks used in Findex.

use std::ffi::{c_int, c_uchar, c_uint};

/// See [`FindexCallbacks::progress()`](crate::core::FindexCallbacks::progress).
///
/// # Serialization
///
/// The intermediate results are serialized as follows:
///
/// `LEB128(results.len()) || serialized_keyword_1
///     || serialized_results_for_keyword_1`
///
/// With the serialization of a keyword being:
///
/// `LEB128(keyword.len()) || keyword`
///
/// the serialization of the values associated to a keyword:
///
/// `LEB128(serialized_results_for_keyword.len()) || serialized_result_1 || ...`
///
/// and the serialization of a result:
///
/// `LEB128(byte_vector.len() + 1) || prefix || byte_vector`
///
/// where `prefix` is `l` (only `Location`s are returned) and the `byte_vector`
/// is the byte representation of the location.
pub type ProgressCallback = extern "C" fn(
    intermediate_results_ptr: *const c_uchar,
    intermediate_results_len: c_uint,
) -> bool;

/// See [`FindexCallbacks::fetch_all_entry_table_uids()`](crate::core::FindexCallbacks::fetch_all_entry_table_uids).
///
/// The output should be deserialized as follows:
///
/// `UID_1 || UID_2 || ... || UID_n`
pub type FetchAllEntryTableUidsCallback =
    extern "C" fn(uids_ptr: *mut c_uchar, uids_len: *mut c_uint) -> c_int;

/// See [`FindexCallbacks::fetch_entry_table()`](crate::core::FindexCallbacks::fetch_entry_table).
///
/// # Serialization
///
/// The input is serialized as follows:
///
/// `LEB128(n_uids) || UID_1 || ...`
///
/// The output should be deserialized as follows:
///
/// `LEB128(n_entries) || UID_1 || LEB128(value_1.len()) || value_1 || ...`
pub type FetchEntryTableCallback = extern "C" fn(
    entries_ptr: *mut c_uchar,
    entries_len: *mut c_uint,
    uids_ptr: *const c_uchar,
    uids_len: c_uint,
) -> c_int;

/// See [`FindexCallbacks::fetch_chain_table()`](crate::core::FindexCallbacks::fetch_chain_table).
///
/// # Serialization
///
/// The input is serialized as follows:
///
/// `LEB128(n_uids) || UID_1 || ...`
///
/// The output should be serialized as follows:
///
/// `LEB128(n_lines) || UID_1 || LEB128(value_1.len()) || value_1 || ...`
pub type FetchChainTableCallback = extern "C" fn(
    chains_ptr: *mut c_uchar,
    chains_len: *mut c_uint,
    uids_ptr: *const c_uchar,
    uids_len: c_uint,
) -> c_int;

/// See [`FindexCallbacks::upsert_entry_table()`](crate::core::FindexCallbacks::upsert_entry_table).
///
/// # Serialization
///
/// The input is serialized as follows:
///
/// ` LEB128(entries.len()) || UID_1
///     || LEB128(old_value_1.len()) || old_value_1
///     || LEB128(new_value_1.len()) || new_value_1
///     || ...`
///
/// The output should be serialized as follows:
///
/// `LEB128(n_lines) || UID_1 || LEB128(value_1.len()) || value_1 || ...`
pub type UpsertEntryTableCallback = extern "C" fn(
    outputs_ptr: *mut c_uchar,
    outputs_len: *mut c_uint,
    entries_ptr: *const c_uchar,
    entries_len: c_uint,
) -> c_int;

/// See [`FindexCallbacks::insert_entry_table()`](crate::core::FindexCallbacks::insert_entry_table).
///
/// # Serialization
///
/// The input is serialized as follows:
///
/// `LEB128(n_lines) || UID_1 || LEB128(value_1.len() || value_1 || ...`
pub type InsertEntryTableCallback =
    extern "C" fn(entries_ptr: *const c_uchar, entries_len: c_uint) -> c_int;

/// See [`FindexCallbacks::insert_chain_table()`](crate::core::FindexCallbacks::insert_chain_table).
///
/// # Serialization
///
/// The input is serialized as follows:
///
/// `LEB128(n_lines) || UID_1 || LEB128(value_1.len() || value_1 || ...`
pub type InsertChainTableCallback =
    extern "C" fn(chains_ptr: *const c_uchar, chains_len: c_uint) -> c_int;

/// See [`FindexCallbacks::remove_entry_table()`](crate::core::FindexCallbacks::remove_entry_table).
///
/// # Serialization
///
/// The input is serialized as follows:
///
/// `LEB128(n_uids) || UID_1 || ...`
pub type RemoveEntryTableCallback =
    extern "C" fn(entries_ptr: *const c_uchar, entries_len: c_uint) -> c_int;

/// See [`FindexCallbacks::remove_chain_table()`](crate::core::FindexCallbacks::remove_chain_table).
///
/// # Serialization
///
/// The input is serialized as follows:
///
/// `LEB128(n_uids) || UID_1 || ...`
pub type RemoveChainTableCallback =
    extern "C" fn(chains_ptr: *const c_uchar, chains_len: c_uint) -> c_int;

/// See
/// [`FindexCallbacks::list_removed_locations()`](crate::core::FindexCallbacks::list_removed_locations).
///
/// # Serialization
///
/// The input is serialized as follows:
///
/// `LEB128(locations.len()) || LEB128(location_bytes_1.len()
///     || location_bytes_1 || ...`
///
/// Outputs should follow the same serialization.
pub type ListRemovedLocationsCallback = extern "C" fn(
    removed_locations_ptr: *mut c_uchar,
    removed_locations_len: *mut c_uint,
    locations_ptr: *const c_uchar,
    locations_len: c_uint,
) -> c_int;
