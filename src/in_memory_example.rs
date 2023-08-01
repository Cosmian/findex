use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    sync::RwLock,
};

use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializer},
    reexport::rand_core::SeedableRng,
    CsRng,
};
use rand::Rng;

use crate::{
    callbacks::FetchChains,
    parameters::{BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KWI_LENGTH, UID_LENGTH},
    structs::EncryptedMultiTable,
    EncryptedTable, FindexCallbacks, FindexCompact, FindexSearch, FindexUpsert, IndexedValue,
    Keyword, Location, Uids, UpsertData,
};

#[derive(Debug)]
pub struct ExampleError(String);

impl Display for ExampleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ExampleError {}

impl crate::CallbackError for ExampleError {}

#[derive(Default)]
pub struct FindexInMemory<const UID_LENGTH: usize> {
    entry_table: RwLock<EncryptedTable<UID_LENGTH>>,
    chain_table: RwLock<EncryptedTable<UID_LENGTH>>,
    removed_locations: HashSet<Location>,
    pub check_progress_callback_next_keyword: bool,
    pub progress_callback_cancel: bool,
}

impl<const UID_LENGTH: usize> FindexInMemory<UID_LENGTH> {
    /// The entry table length (number of records)
    #[must_use]
    pub fn entry_table_len(&self) -> usize {
        self.entry_table
            .read()
            .expect("entry table lock poisoned")
            .len()
    }

    /// The entry table size in bytes
    #[must_use]
    pub fn entry_table_size(&self) -> usize {
        let mut size = 0;
        for (k, v) in self
            .entry_table
            .read()
            .expect("entry table lock poisoned")
            .iter()
        {
            size += k.len() + v.len();
        }
        size
    }

    /// The chain table length (number of records)
    #[must_use]
    pub fn chain_table_len(&self) -> usize {
        self.chain_table
            .read()
            .expect("chain table lock poisoned")
            .len()
    }

    /// The entry table size in bytes
    #[must_use]
    pub fn chain_table_size(&self) -> usize {
        let mut size = 0;
        for (k, v) in self
            .chain_table
            .read()
            .expect("chain table lock poisoned")
            .iter()
        {
            size += k.len() + v.len();
        }
        size
    }

    pub fn remove_location(&mut self, location: Location) {
        self.removed_locations.insert(location);
    }

    pub fn dump_tables(&self) -> Result<Vec<u8>, ExampleError> {
        let mut ser = Serializer::new();
        ser.write(&self.entry_table)
            .map_err(|e| ExampleError(e.to_string()))?;
        ser.write(&self.chain_table)
            .map_err(|e| ExampleError(e.to_string()))?;
        Ok(ser.finalize().to_vec())
    }

    pub fn load_tables(&mut self, bytes: &[u8]) -> Result<(), ExampleError> {
        let mut de = Deserializer::new(bytes);
        self.entry_table = de
            .read::<EncryptedTable<UID_LENGTH>>()
            .map_err(|e| ExampleError(e.to_string()))?;
        self.chain_table = de
            .read::<EncryptedTable<UID_LENGTH>>()
            .map_err(|e| ExampleError(e.to_string()))?;
        if !de.finalize().is_empty() {
            Err(ExampleError(
                "Remaining bytes found after reading index from given bytes".to_string(),
            ))
        } else {
            Ok(())
        }
    }
}

impl<const UID_LENGTH: usize> FindexCallbacks<ExampleError, UID_LENGTH>
    for FindexInMemory<UID_LENGTH>
{
    async fn progress(
        &self,
        results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, ExampleError> {
        if self.check_progress_callback_next_keyword {
            let rob_keyword = Keyword::from("rob");
            let robert_keyword = Keyword::from("robert");
            if let Some(results) = results.get(&rob_keyword) {
                assert!(results.contains(&IndexedValue::NextKeyword(Keyword::from("robert"))));
            } else if let Some(results) = results.get(&robert_keyword) {
                assert!(results.contains(&IndexedValue::Location(Location::from("robert"))));
            } else {
                return Err(ExampleError(
                    "Cannot find keyword 'rob' nor 'robert' in search results".to_string(),
                ));
            }
        }

        Ok(!self.progress_callback_cancel)
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<Uids<UID_LENGTH>, ExampleError> {
        let uids = Uids(
            self.entry_table
                .read()
                .expect("entry table lock poisoned")
                .keys()
                .copied()
                .collect(),
        );
        Ok(uids)
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedMultiTable<UID_LENGTH>, ExampleError> {
        let items = entry_table_uids
            .into_iter()
            .filter_map(|uid| {
                self.entry_table
                    .read()
                    .expect("entry table lock poisoned")
                    .get(&uid)
                    .cloned()
                    .map(|value| (uid, value))
            })
            .collect::<Vec<_>>();
        Ok(EncryptedMultiTable(items))
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, ExampleError> {
        let mut items = EncryptedTable::with_capacity(chain_table_uids.len());
        for uid in chain_table_uids {
            if let Some(value) = self
                .chain_table
                .read()
                .expect("chain table lock poisoned")
                .get(&uid)
            {
                items.insert(uid, value.clone());
            }
        }
        Ok(items)
    }

    async fn upsert_entry_table(
        &self,
        modifications: UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, ExampleError> {
        let mut rng = CsRng::from_entropy();
        let mut rejected = EncryptedTable::default();
        // Simulate insertion failures.
        for (uid, (old_value, new_value)) in modifications {
            // Reject insert with probability 0.2.
            if self
                .entry_table
                .read()
                .expect("entry table lock poisoned")
                .contains_key(&uid)
                && rng.gen_range(0..5) == 0
            {
                rejected.insert(uid, old_value.unwrap_or_default());
            } else {
                self.entry_table
                    .write()
                    .expect("entry table lock poisoned")
                    .insert(uid, new_value);
            }
        }
        Ok(rejected)
    }

    async fn insert_chain_table(
        &self,
        items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), ExampleError> {
        for (uid, value) in items {
            if self
                .chain_table
                .read()
                .expect("entry table lock poisoned")
                .contains_key(&uid)
            {
                return Err(ExampleError(format!(
                    "Conflict in Chain Table for UID: {uid:?}"
                )));
            }
            self.chain_table
                .write()
                .expect("chain table lock poisoned")
                .insert(uid, value);
        }
        Ok(())
    }

    async fn update_lines(
        &self,
        chain_table_uids_to_remove: Uids<UID_LENGTH>,
        new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), ExampleError> {
        *self.entry_table.write().expect("entry table lock poisoned") =
            new_encrypted_entry_table_items;

        for new_encrypted_chain_table_item in new_encrypted_chain_table_items {
            self.chain_table
                .write()
                .expect("chain table lock poisoned")
                .insert(
                    new_encrypted_chain_table_item.0,
                    new_encrypted_chain_table_item.1,
                );
        }

        for removed_chain_table_uid in chain_table_uids_to_remove {
            self.chain_table
                .write()
                .expect("chain table lock poisoned")
                .remove(&removed_chain_table_uid);
        }

        Ok(())
    }

    async fn list_removed_locations(
        &self,
        _: HashSet<Location>,
    ) -> Result<HashSet<Location>, ExampleError> {
        Ok(self.removed_locations.iter().cloned().collect())
    }
}

impl FetchChains<UID_LENGTH, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KWI_LENGTH, ExampleError>
    for FindexInMemory<UID_LENGTH>
{
}

impl_findex_trait!(FindexSearch, FindexInMemory<UID_LENGTH>, ExampleError);

impl_findex_trait!(FindexUpsert, FindexInMemory<UID_LENGTH>, ExampleError);

impl_findex_trait!(FindexCompact, FindexInMemory<UID_LENGTH>, ExampleError);
