//! This module defines the signature of the Findex WASM callbacks.

use std::{
    collections::{HashMap, HashSet},
    fmt::{Display, Formatter},
};

use js_sys::{Array, JsString, Object, Reflect, Uint8Array};
use wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue};

use crate::{
    core::{IndexedValue, Keyword},
    error::FindexErr,
    interfaces::wasm_bindgen::core::utils::get_bytes_from_object_property,
};

#[wasm_bindgen]
extern "C" {
    /// Allows fetching data from Findex indexes.
    ///
    /// See
    /// [`FindexCallbacks::fetch_entry_table()`](crate::core::FindexCallbacks::fetch_entry_table)
    /// and
    /// [`FindexCallbacks::fetch_chain_table()`](crate::core::FindexCallbacks::fetch_chain_table)
    #[wasm_bindgen(
        typescript_type = "(uids: Uint8Array[]) => Promise<{uid: Uint8Array, value: Uint8Array}[]>"
    )]
    pub type Fetch;
}

#[wasm_bindgen]
extern "C" {
    /// See
    /// [`FindexCallbacks::upsert_entry_table()`](crate::core::FindexCallbacks::upsert_entry_table).
    #[wasm_bindgen(
        typescript_type = "(uidsAndValues: {uid: Uint8Array, oldValue: Uint8Array | null, \
                           newValue: Uint8Array}[]) => Promise<{uid: Uint8Array, value: \
                           Uint8Array}[]>"
    )]
    pub type Upsert;
}

#[wasm_bindgen]
extern "C" {
    /// See
    /// [`FindexCallbacks::insert_chain_table()`](crate::core::FindexCallbacks::insert_chain_table).
    #[wasm_bindgen(
        typescript_type = "(uidsAndValues: {uid: Uint8Array, value: Uint8Array}[]) => \
                           Promise<void>"
    )]
    pub type Insert;
}

#[wasm_bindgen]
extern "C" {
    /// See [`FindexCallbacks::progress()`](crate::core::FindexCallbacks::progress).
    #[wasm_bindgen(typescript_type = "(indexedValues: Uint8Array[]) => Promise<Boolean>")]
    pub type Progress;
}

#[wasm_bindgen]
extern "C" {
    /// JS Array of indexed values and their associated keywords to upsert.
    ///
    /// See [`FindexUpsert::upsert()`](crate::core::FindexUpsert::upsert).
    #[wasm_bindgen(typescript_type = "Array<{indexedValue: Uint8Array, keywords: Uint8Array[]}>")]
    #[derive(Debug)]
    pub type IndexedValuesAndWords;
}

pub fn to_indexed_values_to_keywords(
    ivw: &IndexedValuesAndWords,
) -> Result<HashMap<IndexedValue, HashSet<Keyword>>, FindexErr> {
    let array: &Array = ivw.dyn_ref().ok_or_else(|| {
        FindexErr::CallBack(format!(
            "During Findex upsert: `newIndexedEntries` should be an array, {} received.",
            ivw.js_typeof()
                .dyn_ref::<JsString>()
                .map_or_else(|| "unknown type".to_owned(), |s| format!("{s}")),
        ))
    })?;

    let mut iv_and_words = HashMap::new();
    let object_source_for_errors = ObjectSourceForErrors::Argument("newIndexedEntries");
    for (i, try_obj) in array.values().into_iter().enumerate() {
        //{indexedValue: Uint8Array, keywords: Uint8Array[]}
        let obj = try_obj?;
        let iv_bytes =
            get_bytes_from_object_property(&obj, "indexedValue", &object_source_for_errors, i)?;
        let iv = IndexedValue::try_from(iv_bytes.as_slice())?;
        let kw_array = { Array::from(&Reflect::get(&obj, &JsValue::from_str("keywords"))?) };
        let mut words_set: HashSet<Keyword> = HashSet::new();
        for try_bytes in kw_array.values() {
            let bytes = Uint8Array::from(try_bytes?).to_vec();
            let keyword = Keyword::from(bytes);
            words_set.insert(keyword);
        }
        iv_and_words.insert(iv, words_set);
    }
    Ok(iv_and_words)
}

#[wasm_bindgen]
extern "C" {
    /// JS Array of `UInt8Array` used to pass keywords to Findex
    /// [`search`](crate::core::FindexSearch::search) and
    /// [`upsert`](crate::core::FindexUpsert::upsert).
    #[wasm_bindgen(typescript_type = "Array<Uint8Array>")]
    pub type ArrayOfKeywords;
}

#[wasm_bindgen]
extern "C" {
    /// Findex search result type.
    ///
    /// See [`FindexSearch::search()`](crate::core::FindexSearch::search).
    #[wasm_bindgen(typescript_type = "Array<{ keyword: Uint8Array, results: Array<Uint8Array> }>")]
    pub type SearchResults;
}

pub fn search_results_to_js(
    results: &HashMap<Keyword, HashSet<IndexedValue>>,
) -> Result<SearchResults, JsValue> {
    let array = Array::new_with_length(results.len() as u32);
    for (i, (keyword, indexed_values)) in results.iter().enumerate() {
        let obj = Object::new();
        Reflect::set(
            &obj,
            &JsValue::from_str("keyword"),
            &Uint8Array::from(keyword.to_vec().as_slice()),
        )?;
        let sub_array = Array::new_with_length((indexed_values.len()) as u32);
        for (j, value) in indexed_values.iter().enumerate() {
            let js_array = Uint8Array::from(value.to_vec().as_slice());
            sub_array.set(j as u32, js_array.into());
        }
        Reflect::set(&obj, &JsValue::from_str("results"), &sub_array)?;
        array.set(i as u32, obj.into());
    }
    Ok(SearchResults::from(JsValue::from(array)))
}

pub enum ObjectSourceForErrors {
    ReturnedFromCallback(&'static str),
    Argument(&'static str),
}

impl Display for ObjectSourceForErrors {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReturnedFromCallback(name) => write!(f, "inside array returned by {name}"),
            Self::Argument(name) => write!(f, "inside {name}"),
        }
    }
}
