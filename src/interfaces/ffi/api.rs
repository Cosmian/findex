//! Defines the Findex FFI API.

use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    ffi::c_uint,
    num::{NonZeroU32, NonZeroUsize},
    os::raw::{c_char, c_int},
};

use cosmian_crypto_core::bytes_ser_de::{Serializable, Serializer};
use cosmian_ffi::{
    error::{h_get_error, set_last_error, FfiError},
    ffi_read_bytes, ffi_read_string, ffi_unwrap, ffi_write_bytes,
};
use futures::executor;

use super::core::FetchAllEntryTableUidsCallback;
use crate::{
    core::{
        FindexCompact, FindexSearch, FindexUpsert, IndexedValue, KeyingMaterial, Keyword, Label,
    },
    error::FindexErr,
    interfaces::{
        cloud::FindexCloud,
        ffi::{
            core::{
                FetchChainTableCallback, FetchEntryTableCallback, FindexUser,
                InsertChainTableCallback, ListRemovedLocationsCallback, ProgressCallback,
                UpdateLinesCallback, UpsertEntryTableCallback,
            },
            MAX_DEPTH,
        },
        generic_parameters::{
            MASTER_KEY_LENGTH, MAX_RESULTS_PER_KEYWORD, SECURE_FETCH_CHAINS_BATCH_SIZE,
        },
        ser_de::SerializableSet,
    },
};

/// Re-export the `cosmian_ffi` `h_get_error` function to clients with the old
/// `get_last_error` name The `h_get_error` is available inside the final lib
/// (but tools like ffigen seems to not parse it…) Maybe we can find a solution
/// by changing the function name inside the clients.
///
/// # Safety
///
/// It's unsafe.
#[no_mangle]
pub unsafe extern "C" fn get_last_error(error_ptr: *mut c_char, error_len: *mut c_int) -> c_int {
    h_get_error(error_ptr, error_len)
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
/// - `indexed_values`            : (output) search result
/// - `master_key`                : master key
/// - `label`                     : additional information used to derive Entry
///   Table UIDs
/// - `keywords`                  : `serde` serialized list of base64 keywords
/// - `max_results_per_keyword`   : maximum number of results returned per
///   keyword
/// - `max_depth`                 : maximum recursion depth allowed
/// - `progress_callback`         : callback used to retrieve intermediate
///   results and transmit user interrupt
/// - `fetch_entry_callback`      : callback used to fetch the Entry Table
/// - `fetch_chain_callback`      : callback used to fetch the Chain Table
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
    fetch_entry_callback: FetchEntryTableCallback,
    fetch_chain_callback: FetchChainTableCallback,
) -> c_int {
    let master_key_bytes = ffi_read_bytes!("master key", master_key_ptr, master_key_len);
    let master_key = ffi_unwrap!(
        KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(master_key_bytes).map_err(|e| {
            FindexErr::Other(format!("While parsing master key for Findex search, {e}"))
        })
    );

    let label_bytes = ffi_read_bytes!("label", label_ptr, label_len);
    let label = Label::from(label_bytes);

    let max_results_per_keyword = usize::try_from(max_results_per_keyword)
        .ok()
        .and_then(NonZeroUsize::new)
        .unwrap_or(MAX_RESULTS_PER_KEYWORD);

    let max_depth = usize::try_from(max_depth).unwrap_or(MAX_DEPTH);

    // Why keywords are JSON array of base64 strings? We should change this to send
    // raw bytes with leb128 prefix or something like that.
    // <https://github.com/Cosmian/findex/issues/19>

    let keywords_as_json_string = ffi_read_string!("keywords", keywords_ptr);
    let keywords_as_base64_vec: Vec<String> = ffi_unwrap!(
        serde_json::from_str(&keywords_as_json_string),
        "failed deserializing the keywords from JSON"
    );
    let mut keywords = HashSet::with_capacity(keywords_as_base64_vec.len());
    for keyword_as_base64 in keywords_as_base64_vec {
        // base64 decode the words
        let word_bytes = ffi_unwrap!(base64::decode(&keyword_as_base64).map_err(|e| {
            FindexErr::ConversionError(format!(
                "Failed decoding the base64 encoded word: {keyword_as_base64}: {e}"
            ))
        }));
        keywords.insert(Keyword::from(word_bytes));
    }

    let fetch_chains_batch_size = usize::try_from(fetch_chains_batch_size)
        .ok()
        .and_then(NonZeroUsize::new)
        .unwrap_or(SECURE_FETCH_CHAINS_BATCH_SIZE);

    let mut findex = FindexUser {
        progress: Some(progress_callback),
        fetch_entry: Some(fetch_entry_callback),
        fetch_chain: Some(fetch_chain_callback),
        upsert_entry: None,
        insert_chain: None,
        update_lines: None,
        list_removed_locations: None,
        fetch_all_entry_table_uids: None,
    };

    // We want to forward error code returned by callbacks to the parent caller to
    // do error management client side.
    let results = match executor::block_on(findex.search(
        &keywords,
        &master_key,
        &label,
        max_results_per_keyword.into(),
        max_depth,
        fetch_chains_batch_size,
        0,
    )) {
        Ok(results) => results,
        Err(err) => {
            set_last_error(FfiError::Generic(format!("{err}")));
            return match err {
                FindexErr::CallbackErrorCode { code, .. } => code,
                _ => 1,
            };
        }
    };

    // Serialize the results.
    // We should be able to use the output buffer as the Serializer sink to avoid to
    // copy the buffer (right now the crypto_core serializer doesn't provide à
    // constructor from an existing slice)
    // <https://github.com/Cosmian/findex/issues/20>
    let mut serializer = Serializer::new();
    ffi_unwrap!(serializer.write_u64(results.len() as u64));
    for (keyword, locations) in results {
        ffi_unwrap!(serializer.write_vec(&keyword));
        ffi_unwrap!(serializer.write(&SerializableSet(&locations)));
    }
    let serialized_uids = serializer.finalize();

    ffi_write_bytes!(
        "search results",
        &serialized_uids,
        search_results_ptr,
        search_results_len
    );

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
    let master_key_bytes = ffi_read_bytes!("master key", master_key_ptr, master_key_len);
    let master_key = ffi_unwrap!(
        KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(master_key_bytes).map_err(|e| {
            FindexErr::Other(format!("While parsing master key for Findex search, {e}"))
        })
    );

    let label_bytes = ffi_read_bytes!("label", label_ptr, label_len);
    let label = Label::from(label_bytes);

    let indexed_values_and_keywords_as_json_string = ffi_read_string!(
        "indexed values and keywords",
        indexed_values_and_keywords_ptr
    );

    // Indexed values and keywords are a map of base64 encoded `IndexedValue` to a
    // list of base64 encoded keywords. Why that? We should use simple
    // serialization to pass the data and not depend on JSON+base64 to improve
    // perfs.
    // <https://github.com/Cosmian/findex/issues/19>
    let indexed_values_and_keywords_as_base64_hashmap: HashMap<String, Vec<String>> = ffi_unwrap!(
        serde_json::from_str(&indexed_values_and_keywords_as_json_string)
    );

    let mut indexed_values_and_keywords =
        HashMap::with_capacity(indexed_values_and_keywords_as_base64_hashmap.len());
    for (indexed_value, keywords_vec) in indexed_values_and_keywords_as_base64_hashmap {
        let indexed_value_bytes = ffi_unwrap!(base64::decode(indexed_value));
        let indexed_value = ffi_unwrap!(IndexedValue::try_from(indexed_value_bytes.as_slice()));
        let mut keywords = HashSet::with_capacity(keywords_vec.len());
        for keyword in keywords_vec {
            let keyword_bytes = ffi_unwrap!(base64::decode(keyword));
            keywords.insert(Keyword::from(keyword_bytes));
        }
        indexed_values_and_keywords.insert(indexed_value, keywords);
    }

    let mut findex = FindexUser {
        progress: None,
        fetch_entry: Some(fetch_entry),
        fetch_chain: None,
        upsert_entry: Some(upsert_entry),
        insert_chain: Some(insert_chain),
        update_lines: None,
        list_removed_locations: None,
        fetch_all_entry_table_uids: None,
    };

    // We want to forward error code returned by callbacks to the parent caller to
    // do error management client side.
    match executor::block_on(findex.upsert(indexed_values_and_keywords, &master_key, &label)) {
        Ok(_) => 0,
        Err(err) => {
            set_last_error(FfiError::Generic(format!("{err}")));
            match err {
                FindexErr::CallbackErrorCode { code, .. } => code,
                _ => 1,
            }
        }
    }
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
/// - `new_label`                       : additional information used to derive
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
    old_master_key_ptr: *const u8,
    old_master_key_len: c_int,
    new_master_key_ptr: *const u8,
    new_master_key_len: c_int,
    new_label_ptr: *const u8,
    new_label_len: c_int,
    fetch_all_entry_table_uids: FetchAllEntryTableUidsCallback,
    fetch_entry: FetchEntryTableCallback,
    fetch_chain: FetchChainTableCallback,
    update_lines: UpdateLinesCallback,
    list_removed_locations: ListRemovedLocationsCallback,
) -> c_int {
    let num_reindexing_before_full_set = ffi_unwrap!(
        u32::try_from(num_reindexing_before_full_set)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or_else(|| FindexErr::Other(format!(
                "num_reindexing_before_full_set ({num_reindexing_before_full_set}) should be a \
                 non-zero positive integer."
            )))
    );

    let old_master_key_bytes =
        ffi_read_bytes!("master key", old_master_key_ptr, old_master_key_len);
    let old_master_key = ffi_unwrap!(
        KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(old_master_key_bytes).map_err(|e| {
            FindexErr::Other(format!(
                "While parsing the old master key for Findex compact, {e}"
            ))
        })
    );

    let new_master_key_bytes =
        ffi_read_bytes!("new master key", new_master_key_ptr, new_master_key_len);
    let new_master_key = ffi_unwrap!(
        KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(new_master_key_bytes).map_err(|e| {
            FindexErr::Other(format!(
                "While parsing the new master key for Findex compact, {e}"
            ))
        })
    );

    let new_label_bytes = ffi_read_bytes!("new label", new_label_ptr, new_label_len);
    let new_label = Label::from(new_label_bytes);

    let mut findex = FindexUser {
        progress: None,
        fetch_entry: Some(fetch_entry),
        fetch_chain: Some(fetch_chain),
        upsert_entry: None,
        insert_chain: None,
        update_lines: Some(update_lines),
        list_removed_locations: Some(list_removed_locations),
        fetch_all_entry_table_uids: Some(fetch_all_entry_table_uids),
    };

    ffi_unwrap!(executor::block_on(findex.compact(
        num_reindexing_before_full_set.into(),
        &old_master_key,
        &new_master_key,
        &new_label,
    )));

    0
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
pub unsafe extern "C" fn h_search_cloud(
    search_results_ptr: *mut c_char,
    search_results_len: *mut c_int,
    token_ptr: *const c_char,
    label_ptr: *const u8,
    label_len: c_int,
    keywords_ptr: *const c_char,
    max_results_per_keyword: c_int,
    max_depth: c_int,
    fetch_chains_batch_size: c_uint,
) -> c_int {
    //
    // Check arguments
    //
    ffi_not_null!(token_ptr, "Token should not be null");
    let token = match CStr::from_ptr(token_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(e) => {
            set_last_error(FfiErr::Generic(format!(
                "Upsert: invalid IndexedValues and keywords: {e}"
            )));
            return 1;
        }
    };

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

    let findex_cloud = FindexCloud::new(token, None)?;
    let findex_master_key = findex_cloud.token.findex_master_key.clone();

    let rt = tokio::runtime::Runtime::new().unwrap();
    ffi_unwrap!(rt.block_on(findex_cloud.search(&keywords, &findex_master_key, &label,)));

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
/// - `token`           : Findex Cloud token
/// - `label`           : additional information used to derive Entry Table UIDs
/// - `indexed_values_and_keywords` : serialized list of values and the keywords
///   used to index them
///
/// # Safety
///
/// Cannot be safe since using FFI.
pub unsafe extern "C" fn h_upsert_cloud(
    token_ptr: *const c_char,
    label_ptr: *const u8,
    label_len: c_int,
    indexed_values_and_keywords_ptr: *const c_char,
) -> c_int {
    ffi_not_null!(token_ptr, "Token should not be null");
    let token = match CStr::from_ptr(token_ptr).to_str() {
        Ok(msg) => msg.to_owned(),
        Err(e) => {
            set_last_error(FfiErr::Generic(format!(
                "Upsert: invalid IndexedValues and keywords: {e}"
            )));
            return 1;
        }
    };

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
    let mut findex_cloud = ffi_unwrap!(FindexCloud::new(token, None));
    let findex_master_key = findex_cloud.token.findex_master_key.clone();

    let rt = tokio::runtime::Runtime::new().unwrap();
    ffi_unwrap!(rt.block_on(findex_cloud.upsert(
        indexed_values_and_keywords,
        &findex_master_key,
        &label,
    )));

    0
}
