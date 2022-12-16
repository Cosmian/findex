use std::{
    collections::{HashMap, HashSet},
    ffi::{c_uchar, c_uint},
    ptr::null,
};

use cosmian_crypto_core::{
    bytes_ser_de::{Serializable, Serializer},
    symmetric_crypto::Dem,
};

use crate::{
    core::{
        EncryptedTable, FindexCallbacks, FindexCompact, FindexSearch, FindexUpsert, IndexedValue,
        Keyword, Location, Uid, UpsertData,
    },
    error::FindexErr,
    interfaces::{
        ffi::{
            core::{
                utils::{
                    fetch_callback, get_allocation_size_for_select_chain_request,
                    get_serialized_encrypted_entry_table_size_bound,
                },
                FindexUser, NUMBER_OF_ENTRY_TABLE_LINE_IN_BATCH,
            },
            LEB128_MAXIMUM_ENCODED_BYTES_NUMBER,
        },
        generic_parameters::{
            DemScheme, KmacKey, BLOCK_LENGTH, DEM_KEY_LENGTH, KMAC_KEY_LENGTH, KWI_LENGTH,
            MASTER_KEY_LENGTH, TABLE_WIDTH, UID_LENGTH,
        },
        ser_de::{deserialize_set, serialize_set},
    },
};

impl FindexCallbacks<UID_LENGTH> for FindexUser {
    async fn progress(
        &self,
        results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, FindexErr> {
        let progress = unwrap_callback!(self, progress);
        let mut serializer = Serializer::new();
        serializer.write_u64(results.len() as u64)?;
        for (keyword, indexed_values) in results {
            serializer.write_vec(keyword)?;
            serializer.write_vec(&serialize_set(indexed_values)?)?;
        }
        let results = serializer.finalize();
        Ok(progress(results.as_ptr(), results.len() as c_uint))
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: Option<&HashSet<Uid<UID_LENGTH>>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let fetch_entry = unwrap_callback!(self, fetch_entry);
        if let Some(entry_table_uids) = entry_table_uids {
            let serialized_uids = serialize_set(entry_table_uids)?;
            let res = fetch_callback(
                &serialized_uids,
                get_serialized_encrypted_entry_table_size_bound(entry_table_uids.len()),
                *fetch_entry,
            )?;

            EncryptedTable::try_from_bytes(&res)
        } else {
            let allocation_size = (LEB128_MAXIMUM_ENCODED_BYTES_NUMBER
                + { DemScheme::ENCRYPTION_OVERHEAD }
                + DEM_KEY_LENGTH
                + UID_LENGTH
                + LEB128_MAXIMUM_ENCODED_BYTES_NUMBER
                + UID_LENGTH)
                * NUMBER_OF_ENTRY_TABLE_LINE_IN_BATCH;

            let mut uids_and_values = EncryptedTable::default();

            loop {
                let mut output_bytes = vec![0_u8; allocation_size];
                let output_ptr = output_bytes.as_mut_ptr().cast::<c_uchar>();
                let mut output_len = u32::try_from(allocation_size)?;

                let return_code = fetch_entry(output_ptr, &mut output_len, null(), 0);

                if output_len == 0 {
                    break;
                }

                if return_code == 0 || return_code == 1 {
                    let uids_and_values_bytes = unsafe {
                        std::slice::from_raw_parts(output_ptr as *const u8, output_len as usize)
                    };
                    let new_uids_and_values =
                        EncryptedTable::<UID_LENGTH>::try_from_bytes(uids_and_values_bytes)?;
                    for new_item in new_uids_and_values.iter() {
                        uids_and_values.insert(new_item.0.clone(), new_item.1.clone());
                    }
                } else {
                    return Err(FindexErr::CallBack(format!(
                        "Compact: fetch call failed: code={return_code:?} (output_len: \
                         {output_len})"
                    )));
                }

                if return_code == 0 {
                    break;
                }
            }

            Ok(uids_and_values)
        }
    }

    async fn fetch_chain_table(
        &self,
        chain_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let fetch_chain = unwrap_callback!(self, fetch_chain);
        let serialized_chain_uids = serialize_set(chain_uids)?;
        let res = fetch_callback(
            &serialized_chain_uids,
            get_allocation_size_for_select_chain_request(chain_uids.len()),
            *fetch_chain,
        )?;
        EncryptedTable::try_from_bytes(&res)
    }

    async fn upsert_entry_table(
        &mut self,
        modifications: &UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let upsert_entry = unwrap_callback!(self, upsert_entry);

        // Callback input
        let serialized_upsert_data = modifications.try_to_bytes()?;

        // Callback output
        let allocation_size = get_serialized_encrypted_entry_table_size_bound(modifications.len());
        let mut serialized_rejected_items = vec![0; allocation_size];
        let mut serialized_rejected_items_len = allocation_size as u32;
        let serialized_rejected_items_ptr =
            serialized_rejected_items.as_mut_ptr().cast::<c_uchar>();

        // FFI callback
        let return_code = upsert_entry(
            serialized_rejected_items_ptr,
            &mut serialized_rejected_items_len,
            serialized_upsert_data.as_ptr(),
            serialized_upsert_data.len() as u32,
        );

        if return_code != 0 {
            return Err(FindexErr::CallBack(format!(
                "`upsert_entry` failed with code: {return_code}"
            )));
        }

        // Set the correct length for the output.
        unsafe {
            serialized_rejected_items.set_len(serialized_rejected_items_len as usize);
        }

        EncryptedTable::try_from_bytes(&serialized_rejected_items)
    }

    async fn insert_chain_table(
        &mut self,
        items: &EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr> {
        let insert_chain = unwrap_callback!(self, insert_chain);

        // Callback input
        let serialized_items = items.try_to_bytes()?;

        // FFI callback
        insert_chain(serialized_items.as_ptr(), serialized_items.len() as u32);

        Ok(())
    }

    fn update_lines(
        &mut self,
        chain_table_uids_to_remove: HashSet<Uid<UID_LENGTH>>,
        new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr> {
        let update_lines = unwrap_callback!(self, update_lines);

        let serialized_chain_table_uids_to_remove = serialize_set(&chain_table_uids_to_remove)?;
        let serialized_new_encrypted_entry_table_items =
            new_encrypted_entry_table_items.try_to_bytes()?;
        let serialized_new_encrypted_chain_table_items =
            new_encrypted_chain_table_items.try_to_bytes()?;

        let return_code = update_lines(
            serialized_chain_table_uids_to_remove.as_ptr(),
            u32::try_from(serialized_chain_table_uids_to_remove.len())?,
            serialized_new_encrypted_entry_table_items.as_ptr(),
            u32::try_from(serialized_new_encrypted_entry_table_items.len())?,
            serialized_new_encrypted_chain_table_items.as_ptr(),
            u32::try_from(serialized_new_encrypted_chain_table_items.len())?,
        );

        if return_code != 0 {
            return Err(FindexErr::CallBack(format!(
                "Compact: `update_lines` failed with code: {return_code}"
            )));
        }

        Ok(())
    }

    fn list_removed_locations(
        &self,
        locations: &HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexErr> {
        let list_removed_locations = unwrap_callback!(self, list_removed_locations);

        let locations_as_bytes = locations.iter().cloned().collect::<HashSet<_>>();
        let serialized_chain_table_uids_to_remove = serialize_set(&locations_as_bytes)?;

        let mut output_bytes = vec![0_u8; serialized_chain_table_uids_to_remove.len()];
        let output_ptr = output_bytes.as_mut_ptr().cast::<c_uchar>();
        let mut output_len = u32::try_from(serialized_chain_table_uids_to_remove.len())?;

        let return_code = list_removed_locations(
            output_ptr,
            &mut output_len,
            serialized_chain_table_uids_to_remove.as_ptr(),
            u32::try_from(serialized_chain_table_uids_to_remove.len())?,
        );

        if return_code != 0 {
            return Err(FindexErr::CallBack(format!(
                "Compact: list_removed_locations failed (output_len: {output_len})"
            )));
        }

        if output_len == 0 {
            return Ok(HashSet::new());
        }

        let output_locations_bytes =
            unsafe { std::slice::from_raw_parts(output_ptr as *const u8, output_len as usize) };

        let locations = deserialize_set::<Location>(output_locations_bytes)?
            .into_iter()
            .collect();

        Ok(locations)
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
    > for FindexUser
{
}
