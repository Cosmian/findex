use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::bytes_ser_de::Serializable;
use rusqlite::{Connection, OptionalExtension, Result};

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
        ser_de::serialize_set,
        sqlite::utils::{prepare_statement, sqlite_fetch_entry_table_items},
    },
};

pub struct RusqliteFindex<'a> {
    pub connection: &'a mut Connection,
}

impl FindexCallbacks<UID_LENGTH> for RusqliteFindex<'_> {
    async fn progress(
        &self,
        _results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, FindexErr> {
        Ok(true)
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let serialized_res =
            sqlite_fetch_entry_table_items(self.connection, &serialize_set(entry_table_uids)?)?;
        EncryptedTable::try_from_bytes(&serialized_res)
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let mut stmt = prepare_statement(
            self.connection,
            &serialize_set(chain_table_uids)?,
            "chain_table",
        )?;

        let mut rows = stmt.raw_query();
        let mut chain_table_items = EncryptedTable::default();
        while let Some(row) = rows.next()? {
            let uid: Vec<u8> = row.get(0)?;
            chain_table_items.insert(Uid::try_from_bytes(&uid)?, row.get(1)?);
        }
        Ok(chain_table_items)
    }

    async fn upsert_entry_table(
        &mut self,
        items: &UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        let mut rejected_items = EncryptedTable::default();
        let tx = self.connection.transaction()?;
        for (uid, (old_value, new_value)) in items.iter() {
            let actual_value = tx
                .query_row(
                    "SELECT value FROM entry_table WHERE uid = ?1",
                    [uid.to_vec()],
                    |row| row.get::<usize, Vec<u8>>(0),
                )
                .optional()?;
            if actual_value.as_ref() == old_value.as_ref() {
                tx.execute(
                    "REPLACE INTO entry_table (uid, value) VALUES (?1, ?2)",
                    [uid.to_vec(), new_value.clone()],
                )?;
            } else {
                rejected_items.insert(
                    uid.clone(),
                    actual_value.ok_or_else(|| {
                        FindexErr::CallBack(
                            "Index entries cannot be removed while upserting.".to_string(),
                        )
                    })?,
                );
            }
        }
        tx.commit()?;
        Ok(rejected_items)
    }

    async fn insert_chain_table(
        &mut self,
        items: &EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr> {
        let tx = self.connection.transaction()?;
        for (uid, value) in items.iter() {
            tx.execute(
                "INSERT INTO chain_table (uid, value) VALUES (?1, ?2)",
                [uid.to_vec(), value.clone()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn update_lines(
        &mut self,
        _chain_table_uids_to_remove: HashSet<Uid<UID_LENGTH>>,
        _new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        _new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr> {
        // TODO (TBZ): `FindexCompact` is not implemented for `RusqliteFindex`.
        todo!("`FindexCompact` is not implemented for `RusqliteFindex`")
    }

    fn list_removed_locations(
        &self,
        _locations: &HashSet<crate::core::Location>,
    ) -> Result<HashSet<crate::core::Location>, FindexErr> {
        // TODO (TBZ): `FindexCompact` is not implemented for `RusqliteFindex`.
        todo!("`FindexCompact` is not implemented for `RusqliteFindex`")
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<HashSet<Uid<UID_LENGTH>>, FindexErr> {
        todo!("`FindexCompact` is not implemented for `RusqliteFindex`")
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
    > for RusqliteFindex<'_>
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
    > for RusqliteFindex<'_>
{
}
