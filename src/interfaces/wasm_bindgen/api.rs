//! Defines the Findex WASM API.

use std::collections::HashSet;

use cosmian_crypto_core::bytes_ser_de::Serializable;
use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;

use super::core::search_results_to_js;
use crate::{
    core::{FindexSearch, FindexUpsert, KeyingMaterial, Keyword, Label},
    interfaces::{
        generic_parameters::{MASTER_KEY_LENGTH, MAX_RESULTS_PER_KEYWORD},
        wasm_bindgen::core::{
            to_indexed_values_to_keywords, ArrayOfKeywords, Fetch, FindexUser,
            IndexedValuesAndWords, Insert, Progress, SearchResults, Upsert,
        },
    },
};

/// See [`FindexSearch::search()`](crate::core::FindexSearch::search).
///
/// # Parameters
///
/// - `master_key`              : master key
/// - `label_bytes`             : bytes of the public label used for hashing
/// - `keywords`                : list of keyword bytes to search
/// - `max_results_per_keyword` : maximum results returned for a keyword
/// - `max_depth`               : maximum recursion level allowed
/// - `progress`                : progress callback
/// - `fetch_entries`           : callback to fetch from the Entry Table
/// - `fetch_chains`            : callback to fetch from the Chain Table
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub async fn webassembly_search(
    master_key: Uint8Array,
    label_bytes: Uint8Array,
    keywords: ArrayOfKeywords,
    max_results_per_keyword: usize,
    max_depth: usize,
    progress: Progress,
    fetch_entry: Fetch,
    fetch_chain: Fetch,
) -> Result<SearchResults, JsValue> {
    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(&master_key.to_vec())?;
    let label = Label::from(label_bytes.to_vec());

    let keywords: HashSet<_> = Array::from(&JsValue::from(keywords))
        .iter()
        .map(|word| Keyword::from(Uint8Array::new(&word).to_vec()))
        .collect::<HashSet<_>>();

    let max_results_per_keyword = if max_results_per_keyword == 0 {
        MAX_RESULTS_PER_KEYWORD
    } else {
        max_results_per_keyword
    };

    let mut wasm_search = FindexUser {
        progress: Some(progress),
        fetch_entry: Some(fetch_entry),
        fetch_chain: Some(fetch_chain),
        upsert_entry: None,
        insert_chain: None,
    };

    let results = wasm_search
        .search(
            &keywords,
            &master_key,
            &label,
            max_results_per_keyword,
            max_depth,
            0,
        )
        .await?;

    search_results_to_js(&results)
}

/// See [`FindexUpsert::upsert()`](crate::core::FindexUpsert::upsert).
///
/// # Parameters
///
/// - `master_key`                  : master key
/// - `label_bytes`                 : public label used for hashing
/// - `indexed_value_to_keywords`   : map of `IndexedValue`s to `Keyword` bytes
/// - `fetch_entries`               : the callback to fetch from the entry table
/// - `upsert_entries`              : the callback to upsert in the entry table
/// - `insert_chains`               : the callback to insert in the chain table
#[wasm_bindgen]
pub async fn webassembly_upsert(
    master_key: Uint8Array,
    label_bytes: Uint8Array,
    indexed_values_to_keywords: IndexedValuesAndWords,
    fetch_entry: Fetch,
    upsert_entry: Upsert,
    insert_chain: Insert,
) -> Result<(), JsValue> {
    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(&master_key.to_vec())?;
    let label = Label::from(label_bytes.to_vec());
    let indexed_values_to_keywords = to_indexed_values_to_keywords(&indexed_values_to_keywords)?;

    let mut wasm_upsert = FindexUser {
        progress: None,
        fetch_entry: Some(fetch_entry),
        fetch_chain: None,
        upsert_entry: Some(upsert_entry),
        insert_chain: Some(insert_chain),
    };
    wasm_upsert
        .upsert(indexed_values_to_keywords, &master_key, &label)
        .await
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Failed upserting through common search trait: {e}"
            ))
        })
}
