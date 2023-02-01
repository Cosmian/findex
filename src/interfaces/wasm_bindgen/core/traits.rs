use std::collections::{HashMap, HashSet};

use js_sys::{Array, Object};




use super::{
    progress_results_to_js,
    utils::{
        encrypted_table_to_js_value, fetch_uids, js_value_to_encrypted_table,
        set_bytes_in_object_property,
    }, FindexUser,
};
use crate::{
    core::{
        EncryptedTable, FindexCallbacks, FindexSearch, FindexUpsert, IndexedValue, Keyword, Uid,
        UpsertData,
    },
    error::FindexErr,
    interfaces::{
        generic_parameters::{
            DemScheme, KmacKey, BLOCK_LENGTH, DEM_KEY_LENGTH, KMAC_KEY_LENGTH, KWI_LENGTH,
            MASTER_KEY_LENGTH, TABLE_WIDTH, UID_LENGTH,
        },
    },
};

impl FindexCallbacks<UID_LENGTH> for FindexUser {
    async fn progress(
        &self,
        results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, FindexErr> {
        let progress = unwrap_callback!(self, progress);
        let results = progress_results_to_js(results)?;
        let output = callback!(progress, results);
        output.as_bool().ok_or_else(|| {
            FindexErr::CallBack(format!(
                "Progress callback does not return a boolean value: {output:?}"
            ))
        })
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let fetch_entry = unwrap_callback!(self, fetch_entry);
        fetch_uids(
            &entry_table_uids.iter().cloned().collect(),
            fetch_entry,
            "fetchEntries",
        )
        .await
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let fetch_chain = unwrap_callback!(self, fetch_chain);
        fetch_uids(chain_table_uids, fetch_chain, "fetchChains").await
    }

    async fn upsert_entry_table(
        &mut self,
        items: &UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let upsert_entry = unwrap_callback!(self, upsert_entry);

        // Convert input to JS format
        let inputs = Array::new_with_length(items.len() as u32);
        for (index, (uid, (old_value, new_value))) in items.iter().enumerate() {
            let obj = Object::new();
            set_bytes_in_object_property(&obj, "uid", Some(uid)).map_err(|e| {
                FindexErr::CallBack(format!(
                    "Cannot convert UID bytes into object property: {e:?}"
                ))
            })?;
            set_bytes_in_object_property(&obj, "oldValue", old_value.as_deref()).map_err(|e| {
                FindexErr::CallBack(format!(
                    "Cannot convert old value bytes into object property: {e:?}"
                ))
            })?;
            set_bytes_in_object_property(&obj, "newValue", Some(new_value)).map_err(|e| {
                FindexErr::CallBack(format!(
                    "Cannot convert new value bytes into object property: {e:?}"
                ))
            })?;
            inputs.set(index as u32, obj.into());
        }

        let result = callback!(upsert_entry, inputs);
        js_value_to_encrypted_table(&result, "upsertEntries")
    }

    async fn insert_chain_table(
        &mut self,
        items: &EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr> {
        let insert_chain = unwrap_callback!(self, insert_chain);
        let input = encrypted_table_to_js_value(items).map_err(|e| {
            FindexErr::CallBack(format!(
                "Failed to convert Encrypted Table into a JS array: {e:?}"
            ))
        })?;

        callback!(insert_chain, input);
        Ok(())
    }

    fn update_lines(
        &mut self,
        _chain_table_uids_to_remove: HashSet<Uid<UID_LENGTH>>,
        _new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        _new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr> {
        todo!("update lines not implemented in WASM")
    }

    fn list_removed_locations(
        &self,
        _locations: &HashSet<crate::core::Location>,
    ) -> Result<HashSet<crate::core::Location>, FindexErr> {
        todo!("list removed locations not implemented in WASM")
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<HashSet<Uid<UID_LENGTH>>, FindexErr> {
        todo!("fetch all entry table uids not implemented in WASM")
    }
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
    > for FindexUser
{
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
    > for FindexUser
{
}
