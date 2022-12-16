use std::collections::{HashMap, HashSet};

use futures::executor::block_on;
use pyo3::{
    prelude::*,
    types::{PyBytes, PyDict},
};

use crate::{
    core::{
        EncryptedTable, FindexCallbacks, FindexCompact, FindexSearch, FindexUpsert,
        IndexedValue as IndexedValueRust, Keyword, Location, Uid, UpsertData,
    },
    error::FindexErr,
    interfaces::{
        generic_parameters::{
            DemScheme, KmacKey, BLOCK_LENGTH, DEM_KEY_LENGTH, KMAC_KEY_LENGTH, KWI_LENGTH,
            MASTER_KEY_LENGTH, TABLE_WIDTH, UID_LENGTH,
        },
        pyo3::py_structs::{
            IndexedValue as IndexedValuePy, Label as LabelPy, MasterKey as MasterKeyPy,
        },
    },
};

#[pyclass(subclass)]
pub struct InternalFindex {
    fetch_entry: PyObject,
    fetch_chain: PyObject,
    upsert_entry: PyObject,
    insert_chain: PyObject,
    update_lines: PyObject,
    list_removed_locations: PyObject,
    progress_callback: PyObject,
}

impl FindexCallbacks<UID_LENGTH> for InternalFindex {
    async fn progress(
        &self,
        results: &HashMap<Keyword, HashSet<IndexedValueRust>>,
    ) -> Result<bool, FindexErr> {
        let py_results = results
            .iter()
            .map(|(keyword, indexed_values)| {
                (
                    format!("{keyword:?}"),
                    indexed_values
                        .iter()
                        .map(|value| IndexedValuePy(value.clone()))
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<HashMap<_, _>>();

        Python::with_gil(|py| {
            let ret = self
                .progress_callback
                .call1(py, (py_results,))
                .map_err(|e| FindexErr::CallBack(format!("{e} (progress_callback)")))?;

            ret.extract(py)
                .map_err(|e| FindexErr::ConversionError(format!("{e} (progress_callback)")))
        })
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: Option<&HashSet<Uid<UID_LENGTH>>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        Python::with_gil(|py| {
            let py_entry_uids = entry_table_uids.map(|uids| {
                uids.iter()
                    .map(|uid| PyBytes::new(py, uid))
                    .collect::<Vec<_>>()
            });
            let results = self
                .fetch_entry
                .call1(py, (py_entry_uids,))
                .map_err(|e| FindexErr::CallBack(format!("{e} (fetch_entry)")))?;
            let py_result_table: HashMap<[u8; UID_LENGTH], Vec<u8>> = results
                .extract(py)
                .map_err(|e| FindexErr::ConversionError(format!("{e} (fetch_entry)")))?;

            // Convert python result (HashMap<[u8; UID_LENGTH], Vec<u8>>) to
            // EncryptedEntryTable<UID_LENGTH>
            let entry_table_items = py_result_table
                .into_iter()
                .map(|(k, v)| (Uid::from(k), v))
                .collect::<HashMap<_, _>>();

            Ok(entry_table_items.into())
        })
    }

    async fn fetch_chain_table(
        &self,
        chain_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        Python::with_gil(|py| {
            let py_chain_uids = chain_uids
                .iter()
                .map(|uid| PyBytes::new(py, uid))
                .collect::<Vec<_>>();

            let result = self
                .fetch_chain
                .call1(py, (py_chain_uids,))
                .map_err(|e| FindexErr::CallBack(format!("{e} (fetch_chain)")))?;

            let py_result_table: HashMap<[u8; UID_LENGTH], Vec<u8>> = result
                .extract(py)
                .map_err(|e| FindexErr::ConversionError(format!("{e} (fetch_chain)")))?;

            // Convert python result (HashMap<[u8; UID_LENGTH], Vec<u8>>) to
            // EncryptedTable<UID_LENGTH>
            let chain_table_items = py_result_table
                .into_iter()
                .map(|(k, v)| (Uid::from(k), v))
                .collect::<HashMap<_, _>>();
            Ok(chain_table_items.into())
        })
    }

    async fn upsert_entry_table(
        &mut self,
        items: &UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let empty_vec = &vec![];
        Python::with_gil(|py| {
            let py_entry_table = PyDict::new(py);
            for (key, (old_value, new_value)) in items.iter() {
                py_entry_table
                    .set_item(
                        PyBytes::new(py, key),
                        (
                            PyBytes::new(py, old_value.as_ref().unwrap_or(empty_vec)),
                            PyBytes::new(py, new_value),
                        ),
                    )
                    .map_err(|e| FindexErr::ConversionError(format!("{e} (upsert_entry)")))?;
            }

            let rejected_lines = self
                .upsert_entry
                .call1(py, (py_entry_table,))
                .map_err(|e| FindexErr::CallBack(format!("{e} (upsert_entry)")))?;

            let rejected_lines: HashMap<[u8; UID_LENGTH], Vec<u8>> = rejected_lines
                .extract(py)
                .map_err(|e| FindexErr::ConversionError(format!("{e} (upsert_entry)")))?;

            let rejected_lines = rejected_lines
                .into_iter()
                .map(|(k, v)| (Uid::from(k), v))
                .collect::<HashMap<_, _>>();

            Ok(rejected_lines.into())
        })
    }

    async fn insert_chain_table(
        &mut self,
        items: &EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr> {
        Python::with_gil(|py| {
            let py_chain_table = PyDict::new(py);
            for (key, value) in items.iter() {
                py_chain_table
                    .set_item(PyBytes::new(py, key), PyBytes::new(py, value))
                    .map_err(|e| FindexErr::ConversionError(format!("{e} (insert_chain)")))?;
            }
            self.insert_chain
                .call1(py, (py_chain_table,))
                .map_err(|e| FindexErr::CallBack(format!("{e} (insert_chain)")))?;
            Ok(())
        })
    }

    fn update_lines(
        &mut self,
        chain_table_uids_to_remove: HashSet<Uid<UID_LENGTH>>,
        new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr> {
        Python::with_gil(|py| {
            let py_entry_table_items = PyDict::new(py);
            for (key, value) in new_encrypted_entry_table_items.iter() {
                py_entry_table_items
                    .set_item(PyBytes::new(py, key), PyBytes::new(py, value))
                    .map_err(|e| FindexErr::ConversionError(format!("{e} (update_lines)")))?;
            }

            let py_removed_chain_uids: Vec<&PyBytes> = chain_table_uids_to_remove
                .iter()
                .map(|item| PyBytes::new(py, item))
                .collect();

            let py_chain_table_items = PyDict::new(py);
            for (key, value) in new_encrypted_chain_table_items.iter() {
                py_chain_table_items
                    .set_item(PyBytes::new(py, key), PyBytes::new(py, value))
                    .map_err(|e| FindexErr::ConversionError(format!("{e} (update_lines)")))?;
            }

            self.update_lines
                .call1(
                    py,
                    (
                        py_removed_chain_uids,
                        py_entry_table_items,
                        py_chain_table_items,
                    ),
                )
                .map_err(|e| FindexErr::CallBack(format!("{e} (update_lines)")))?;

            Ok(())
        })
    }

    fn list_removed_locations(
        &self,
        locations: &HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexErr> {
        Python::with_gil(|py| {
            let location_bytes: Vec<&PyBytes> =
                locations.iter().map(|l| PyBytes::new(py, l)).collect();

            let result = self
                .list_removed_locations
                .call1(py, (location_bytes,))
                .map_err(|e| FindexErr::CallBack(format!("{e} (list_removed_locations)")))?;

            let py_result: Vec<&[u8]> = result
                .extract(py)
                .map_err(|e| FindexErr::ConversionError(format!("{e} (list_removed_locations)")))?;

            Ok(py_result
                .iter()
                .map(|bytes| Location::from(*bytes))
                .collect())
        })
    }
}

impl
    FindexUpsert<
        UID_LENGTH,
        BLOCK_LENGTH,
        TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
    > for InternalFindex
{
}

impl
    FindexSearch<
        UID_LENGTH,
        BLOCK_LENGTH,
        TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
    > for InternalFindex
{
}

impl
    FindexCompact<
        UID_LENGTH,
        BLOCK_LENGTH,
        TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
    > for InternalFindex
{
}

#[pymethods]
impl InternalFindex {
    #[new]
    pub fn new(py: Python) -> PyResult<Self> {
        let default_callback: Py<PyAny> = PyModule::from_code(
            py,
            "def default_callback(*args, **kwargs):
                raise NotImplementedError()",
            "",
            "",
        )?
        .getattr("default_callback")?
        .into();

        Ok(Self {
            fetch_entry: default_callback.clone(),
            fetch_chain: default_callback.clone(),
            upsert_entry: default_callback.clone(),
            insert_chain: default_callback.clone(),
            update_lines: default_callback.clone(),
            list_removed_locations: default_callback.clone(),
            progress_callback: default_callback,
        })
    }

    /// Sets the required callbacks to implement [`FindexUpsert`].
    pub fn set_upsert_callbacks(
        &mut self,
        fetch_entry: PyObject,
        fetch_chain: PyObject,
        upsert_entry: PyObject,
        insert_chain: PyObject,
    ) {
        self.fetch_entry = fetch_entry;
        self.fetch_chain = fetch_chain;
        self.upsert_entry = upsert_entry;
        self.insert_chain = insert_chain
    }

    /// Sets the required callbacks to implement [`FindexSearch`].
    pub fn set_search_callbacks(
        &mut self,
        fetch_entry: PyObject,
        fetch_chain: PyObject,
        progress_callback: PyObject,
    ) {
        self.fetch_entry = fetch_entry;
        self.fetch_chain = fetch_chain;
        self.progress_callback = progress_callback;
    }

    /// Sets the required callbacks to implement [`FindexCompact`].
    pub fn set_compact_callbacks(
        &mut self,
        fetch_entry: PyObject,
        fetch_chain: PyObject,
        update_lines: PyObject,
        list_removed_locations: PyObject,
    ) {
        self.fetch_entry = fetch_entry;
        self.fetch_chain = fetch_chain;
        self.update_lines = update_lines;
        self.list_removed_locations = list_removed_locations;
    }

    /// Upserts the given relations between `IndexedValue` and `Keyword` into
    /// Findex tables. After upserting, any search for a `Word` given in the
    /// aforementioned relations will result in finding (at least) the
    /// corresponding `IndexedValue`.
    ///
    /// Parameters
    ///
    /// - `indexed_values_and_strings`  : map of `IndexedValue` to keywords
    /// - `master_key`                  : Findex master key
    /// - `label`                       : label used to allow versioning
    pub fn upsert_wrapper(
        &mut self,
        indexed_values_and_strings: HashMap<IndexedValuePy, Vec<&str>>,
        master_key: &MasterKeyPy,
        label: &LabelPy,
    ) -> PyResult<()> {
        let mut indexed_values_and_keywords =
            HashMap::with_capacity(indexed_values_and_strings.len());
        for (indexed_value, strings) in indexed_values_and_strings {
            let mut keywords = HashSet::with_capacity(strings.len());
            for string in strings {
                keywords.insert(Keyword::from(string));
            }
            indexed_values_and_keywords.insert(indexed_value.0, keywords);
        }
        let future = self.upsert(indexed_values_and_keywords, &master_key.0, &label.0);
        block_on(future).map_err(PyErr::from)
    }

    /// Recursively search Findex graphs for `Location` corresponding to the
    /// given `Keyword`.
    ///
    /// Parameters
    ///
    /// - `keywords`                : keywords to search using Findex
    /// - `master_key`              : user secret key
    /// - `label`                   : public label used in keyword hashing
    /// - `max_results_per_keyword` : maximum number of results to fetch per
    ///   keyword
    /// - `max_depth`               : maximum recursion level allowed
    ///
    /// Returns: List[IndexedValue]
    // use `u32::MAX` for `max_result_per_keyword`
    #[args(max_result_per_keyword = "4294967295")]
    #[args(max_depth = "100")]
    pub fn search_wrapper(
        &mut self,
        keywords: Vec<&str>,
        master_key: &MasterKeyPy,
        label: &LabelPy,
        max_result_per_keyword: usize,
        max_depth: usize,
    ) -> PyResult<HashMap<String, Vec<IndexedValuePy>>> {
        let keywords_set: HashSet<Keyword> = keywords
            .iter()
            .map(|keyword| Keyword::from(*keyword))
            .collect();

        let results = block_on(self.search(
            &keywords_set,
            &master_key.0,
            &label.0,
            max_result_per_keyword,
            max_depth,
            0,
        ))?;

        results
            .into_iter()
            .map(
                |(keyword, indexed_values)| -> Result<(String, Vec<IndexedValuePy>), FindexErr> {
                    Ok((
                        keyword.try_into_string()?,
                        indexed_values.into_iter().map(IndexedValuePy).collect(),
                    ))
                },
            )
            .collect::<Result<_, _>>()
            .map_err(PyErr::from)
    }

    /// Replace all the previous Index Entry Table UIDs and
    /// values with new ones (UID will be re-hash with the new label and
    /// values will be re-encrypted with a new nonce).
    /// This function will also select a random portion of all the index entries
    /// and recreate the associated chains without removed `Location` from
    /// the main database.
    ///
    /// Parameters
    ///
    /// - `num_reindexing_before_full_set` : see below
    /// - `master_key`                     : master key
    /// - `new_master_key`                 : newly generated key
    /// - `new_label`                      : newly generated label
    ///
    /// `num_reindexing_before_full_set`: if you compact the
    /// indexes every night this is the number of days to wait before
    /// being sure that a big portion of the indexes were checked
    /// (see the coupon problem to understand why it's not 100% sure)
    pub fn compact_wrapper(
        &mut self,
        num_reindexing_before_full_set: u32,
        master_key: &MasterKeyPy,
        new_master_key: &MasterKeyPy,
        new_label: &LabelPy,
    ) -> PyResult<()> {
        block_on(self.compact(
            num_reindexing_before_full_set,
            &master_key.0,
            &new_master_key.0,
            &new_label.0,
        ))
        .map_err(PyErr::from)
    }
}
