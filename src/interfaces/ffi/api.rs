//! Defines the Findex FFI API.

use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    ffi::{c_uint, CStr},
    num::NonZeroUsize,
    os::raw::{c_char, c_int},
    slice,
};

use cosmian_crypto_core::bytes_ser_de::{Serializable, Serializer};
use futures::executor;

use super::core::FetchAllEntryTableUidsCallback;
use crate::{
    core::{
        FindexCompact, FindexSearch, FindexUpsert, IndexedValue, KeyingMaterial, Keyword, Label,
    },
    error::FindexErr,
    ffi_bail, ffi_not_null, ffi_unwrap,
    interfaces::{
        ffi::{
            core::{
                FetchChainTableCallback, FetchEntryTableCallback, FindexUser,
                InsertChainTableCallback, ListRemovedLocationsCallback, ProgressCallback,
                UpdateLinesCallback, UpsertEntryTableCallback,
            },
            error::{set_last_error, FfiErr},
            MAX_DEPTH,
        },
        generic_parameters::{
            MASTER_KEY_LENGTH, MAX_RESULTS_PER_KEYWORD, SECURE_FETCH_CHAINS_BATCH_SIZE,
        },
        ser_de::SerializableSet,
    },
};

/// Search
///  - `base64_keywords`        : an array of base64 encoded `Keyword` bytes
///  - `master_key_bytes`       : the bytes of the serialized master key
///  - `label_bytes`            : additional information used to derive Entry
///    Table UIDs
///  - `max_results_per_keyword`: maximum number of results to return per
///    keyword
/// - `max_depth`               : maximum recursion depth allowed
/// - `progress_callback`       : callback used to retrieve intermediate results
///   and transmit user interrupt
///  - `fetch_entry`            : the callback function to fetch the values from
///    the Entry Table
///  - `fetch_chain`            : the callback function to fetch the values from
///    the Chain Table
#[allow(clippy::too_many_arguments)]
async fn ffi_search(
    base64_keywords: &[String],
    master_key_bytes: &[u8],
    label_bytes: &[u8],
    max_results_per_keyword: usize,
    max_depth: usize,
    fetch_chains_batch_size: NonZeroUsize,
    progress: ProgressCallback,
    fetch_entry: FetchEntryTableCallback,
    fetch_chain: FetchChainTableCallback,
) -> Result<Vec<u8>, FindexErr> {
    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(master_key_bytes)
        .map_err(|e| {
            FindexErr::Other(format!("While parsing master key for Findex search, {e}"))
        })?;
    let label = Label::from(label_bytes);

    let mut keywords = HashSet::with_capacity(base64_keywords.len());
    for base64_keyword in base64_keywords {
        // base64 decode the words
        let word_bytes = base64::decode(base64_keyword).map_err(|e| {
            FindexErr::ConversionError(format!(
                "Failed decoding the base64 encoded word: {base64_keyword}: {e}"
            ))
        })?;
        keywords.insert(Keyword::from(word_bytes));
    }

    let mut ffi_search = FindexUser {
        progress: Some(progress),
        fetch_entry: Some(fetch_entry),
        fetch_chain: Some(fetch_chain),
        upsert_entry: None,
        insert_chain: None,
        update_lines: None,
        list_removed_locations: None,
        fetch_all_entry_table_uids: None,
    };

    let res = ffi_search
        .search(
            &keywords,
            &master_key,
            &label,
            max_results_per_keyword,
            max_depth,
            fetch_chains_batch_size,
            0,
        )
        .await?;

    // Serialize the results.
    let mut serializer = Serializer::new();
    serializer.write_u64(res.len() as u64)?;
    for (keyword, locations) in res {
        serializer.write_vec(&keyword)?;
        serializer.write(&SerializableSet(&locations))?;
    }
    Ok(serializer.finalize())
}

#[no_mangle]
/// Recursively searches Findex graphs for values indexed by the given keywords.
///
/// # Serialization
///
/// Le output is serialized as follows:
///
/// `LEB128(n_keywords) || LEB128(keyword_1)
///     || keyword_1 || LEB128(n_associated_results)
///     || LEB128(associated_result_1) || associated_result_1
///     || ...`
///
/// # Parameters
///
/// - `indexed_values`          : (output) search result
/// - `master_key`              : master key
/// - `label`                   : additional information used to derive Entry
///   Table UIDs
/// - `keywords`                : `serde` serialized list of base64 keywords
/// - `max_results_per_keyword` : maximum number of results returned per keyword
/// - `max_depth`               : maximum recursion depth allowed
/// - `progress_callback`       : callback used to retrieve intermediate results
///   and transmit user interrupt
/// - `fetch_entry`             : callback used to fetch the Entry Table
/// - `fetch_chain`             : callback used to fetch the Chain Table
///
/// # Safety
///
/// Cannot be safe since using FFI.
pub unsafe extern "C" fn h_search(
    search_results_ptr: *mut c_char,
    search_results_len: *mut c_int,
    master_key_ptr: *const c_char,
    master_key_len: c_int,
    label_ptr: *const u8,
    label_len: c_int,
    keywords_ptr: *const c_char,
    max_results_per_keyword: c_int,
    max_depth: c_int,
    fetch_chains_batch_size: c_uint,
    progress_callback: ProgressCallback,
    fetch_entry: FetchEntryTableCallback,
    fetch_chain: FetchChainTableCallback,
) -> c_int {
    //
    // Check arguments
    //
    ffi_not_null!(
        search_results_ptr,
        "The Locations pointer should point to pre-allocated memory"
    );

    if *search_results_len <= 0 {
        ffi_bail!("The Locations length must be strictly positive");
    }

    let max_results_per_keyword = if max_results_per_keyword <= 0 {
        MAX_RESULTS_PER_KEYWORD
    } else {
        ffi_unwrap!(
            usize::try_from(max_results_per_keyword),
            "loop_iteration_limit must be a positive int"
        )
    };

    let max_depth = if max_depth < 0 {
        MAX_DEPTH
    } else {
        ffi_unwrap!(
            usize::try_from(max_depth),
            "loop_iteration_limit must be a positive int"
        )
    };

    //
    // key k deserialization
    ffi_not_null!(master_key_ptr, "The Key k pointer should not be null");
    let master_key_bytes =
        std::slice::from_raw_parts(master_key_ptr.cast::<u8>(), master_key_len as usize);

    //
    // Label deserialization
    ffi_not_null!(label_ptr, "The Label pointer should not be null");
    let label_bytes = std::slice::from_raw_parts(label_ptr, label_len as usize);

    //
    // Parse keywords
    //
    ffi_not_null!(keywords_ptr, "Keywords pointer should not be null");
    let keywords = match CStr::from_ptr(keywords_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(e) => {
            set_last_error(FfiErr::Generic(format!(
                "convert keywords buffer to String failed: {e}"
            )));
            return 1;
        }
    };
    let base64_keywords: Vec<String> = ffi_unwrap!(
        serde_json::from_str(&keywords),
        "failed deserializing the base64 `Keyword`s"
    );

    let fetch_chains_batch_size = usize::try_from(fetch_chains_batch_size)
        .ok()
        .and_then(NonZeroUsize::new)
        .unwrap_or(SECURE_FETCH_CHAINS_BATCH_SIZE);

    let serialized_uids = ffi_unwrap!(executor::block_on(ffi_search(
        &base64_keywords,
        master_key_bytes,
        label_bytes,
        max_results_per_keyword,
        max_depth,
        fetch_chains_batch_size,
        progress_callback,
        fetch_entry,
        fetch_chain,
    )));

    //
    // Prepare output
    let allocated = *search_results_len;
    let len = serialized_uids.len();
    *search_results_len = len as c_int;
    if (allocated as usize) < len {
        ffi_bail!(
            "The pre-allocated IndexedValues buffer is too small; need {} bytes, allocated {}",
            len,
            allocated
        );
    }
    std::slice::from_raw_parts_mut(search_results_ptr.cast::<u8>(), len)
        .copy_from_slice(&serialized_uids);
    0
}

#[no_mangle]
/// Index the given values for the given keywords. After upserting, any
/// search for such a keyword will result in finding (at least) the
/// corresponding value.
///
/// # Serialization
///
/// The list of values to index for the associated keywords should be serialized
/// as follows:
///
/// `LEB128(n_values) || serialized_value_1
///     || LEB128(n_associated_keywords) || serialized_keyword_1 || ...`
///
/// where values serialized as follows:
///
/// `LEB128(value_bytes.len() + 1) || base64(prefix || value_bytes)`
///
/// with `prefix` being `l` for a `Location` and `w` for a `NextKeyword`, and
/// where keywords are serialized as follows:
///
/// `LEB128(keyword_bytes.len()) || base64(keyword_bytes)`
///
/// # Parameters
///
/// - `master_key`      : Findex master key
/// - `label`           : additional information used to derive Entry Table UIDs
/// - `indexed_values_and_keywords` : serialized list of values and the keywords
///   used to index them
/// - `fetch_entry`     : callback used to fetch the Entry Table
/// - `upsert_entry`    : callback used to upsert lines in the Entry Table
/// - `insert_chain`    : callback used to insert lines in the Chain Table
///
/// # Safety
///
/// Cannot be safe since using FFI.
pub unsafe extern "C" fn h_upsert(
    master_key_ptr: *const u8,
    master_key_len: c_int,
    label_ptr: *const u8,
    label_len: c_int,
    indexed_values_and_keywords_ptr: *const c_char,
    fetch_entry: FetchEntryTableCallback,
    upsert_entry: UpsertEntryTableCallback,
    insert_chain: InsertChainTableCallback,
) -> c_int {
    //
    // Parse master Key
    ffi_not_null!(master_key_ptr, "Master Key pointer should not be null");
    let master_key_bytes = slice::from_raw_parts(master_key_ptr, master_key_len as usize);
    let master_key = ffi_unwrap!(
        KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(master_key_bytes).map_err(|e| {
            FindexErr::Other(format!("while parsing master key for Findex upsert, {e}"))
        })
    );

    ffi_not_null!(label_ptr, "Label pointer should not be null");

    let label_bytes = slice::from_raw_parts(label_ptr, label_len as usize);
    let label = Label::from(label_bytes);

    //
    // Parse IndexedValues and corresponding keywords
    ffi_not_null!(
        indexed_values_and_keywords_ptr,
        "IndexedValues and corresponding keywords pointer should not be null"
    );

    let parsed_indexed_values_and_keywords =
        match CStr::from_ptr(indexed_values_and_keywords_ptr).to_str() {
            Ok(msg) => msg.to_owned(),
            Err(e) => {
                set_last_error(FfiErr::Generic(format!(
                    "Upsert: invalid IndexedValues and keywords: {e}"
                )));
                return 1;
            }
        };
    // a map of base64 encoded `IndexedValue` to a list of base64 encoded keyWords
    let parsed_indexed_values_and_keywords = ffi_unwrap!(serde_json::from_str::<
        HashMap<String, Vec<String>>,
    >(&parsed_indexed_values_and_keywords));
    // the decoded map
    let mut indexed_values_and_keywords =
        HashMap::with_capacity(parsed_indexed_values_and_keywords.len());
    for (key, value) in parsed_indexed_values_and_keywords {
        let iv_bytes = ffi_unwrap!(base64::decode(key));
        let indexed_value = ffi_unwrap!(IndexedValue::try_from(iv_bytes.as_slice()));
        let mut keywords = HashSet::with_capacity(value.len());
        for keyword in value {
            let keyword_bytes = ffi_unwrap!(base64::decode(keyword));
            keywords.insert(Keyword::from(keyword_bytes));
        }
        indexed_values_and_keywords.insert(indexed_value, keywords);
    }

    //
    // Finally write indexes in database
    //
    let mut ffi_upsert = FindexUser {
        progress: None,
        fetch_entry: Some(fetch_entry),
        fetch_chain: None,
        upsert_entry: Some(upsert_entry),
        insert_chain: Some(insert_chain),
        update_lines: None,
        list_removed_locations: None,
        fetch_all_entry_table_uids: None,
    };

    ffi_unwrap!(executor::block_on(ffi_upsert.upsert(
        indexed_values_and_keywords,
        &master_key,
        &label,
    )));

    0
}

#[no_mangle]
/// Replaces all the Index Entry Table UIDs and values. New UIDs are derived
/// using the given label and the KMAC key derived from the new master key. The
/// values are dectypted using the DEM key derived from the master key and
/// re-encrypted using the DEM key derived from the new master key.
///
/// Randomly selects index entries and recompact their associated chains. Chains
/// indexing no existing location are removed. Others are recomputed from a new
/// keying material. This removes unneeded paddings. New UIDs are derived for
/// the chain and values are re-encrypted using a DEM key derived from the new
/// keying material.
///
/// # Parameters
///
/// - `num_reindexing_before_full_set`  : number of compact operation needed to
///   compact all Chain Table
/// - `old_master_key`                  : old Findex master key
/// - `new_master_key`                  : new Findex master key
/// - `label`                           : additional information used to derive
///   Entry Table UIDs
/// - `fetch_entry`                     : callback used to fetch the Entry Table
/// - `fetch_chain`                     : callback used to fetch the Chain Table
/// - `update_lines`                    : callback used to update lines in both
///   tables
/// - `list_removed_locations`          : callback used to list removed
///   locations among the ones given
///
/// # Safety
///
/// Cannot be safe since using FFI.
pub unsafe extern "C" fn h_compact(
    num_reindexing_before_full_set: c_int,
    master_key_ptr: *const u8,
    master_key_len: c_int,
    new_master_key_ptr: *const u8,
    new_master_key_len: c_int,
    label_ptr: *const u8,
    label_len: c_int,
    fetch_all_entry_table_uids: FetchAllEntryTableUidsCallback,
    fetch_entry: FetchEntryTableCallback,
    fetch_chain: FetchChainTableCallback,
    update_lines: UpdateLinesCallback,
    list_removed_locations: ListRemovedLocationsCallback,
) -> c_int {
    let num_reindexing_before_full_set = match num_reindexing_before_full_set.try_into() {
        Ok(uint) => uint,
        Err(e) => {
            set_last_error(FfiErr::Generic(format!(
                "num_reindexing_before_full_set ({num_reindexing_before_full_set}) should be a \
                 positive uint. {e}"
            )));
            return 1;
        }
    };

    //
    // Parse master Key
    ffi_not_null!(master_key_ptr, "Master Key pointer should not be null");
    let master_key_bytes = slice::from_raw_parts(master_key_ptr, master_key_len as usize);
    let master_key = ffi_unwrap!(KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(
        master_key_bytes
    ));
    let new_master_key_bytes =
        slice::from_raw_parts(new_master_key_ptr, new_master_key_len as usize);
    let new_master_key = ffi_unwrap!(KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(
        new_master_key_bytes
    ));

    ffi_not_null!(label_ptr, "Label pointer should not be null");

    let label_bytes = slice::from_raw_parts(label_ptr, label_len as usize);
    let label = Label::from(label_bytes);

    //
    // Finally write indexes in database
    //
    let mut ffi_compact = FindexUser {
        progress: None,
        fetch_entry: Some(fetch_entry),
        fetch_chain: Some(fetch_chain),
        upsert_entry: None,
        insert_chain: None,
        update_lines: Some(update_lines),
        list_removed_locations: Some(list_removed_locations),
        fetch_all_entry_table_uids: Some(fetch_all_entry_table_uids),
    };

    ffi_unwrap!(executor::block_on(ffi_compact.compact(
        num_reindexing_before_full_set,
        &master_key,
        &new_master_key,
        &label,
    )));

    0
}
