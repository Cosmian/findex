use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
use rand::Rng;

#[cfg(feature = "live_compact")]
use crate::{compact_live::FindexLiveCompact, parameters::*};
use crate::{
    parameters::UID_LENGTH, EncryptedTable, FindexCallbacks, FindexCompact, FindexSearch,
    FindexUpsert, IndexedValue, Keyword, Location, Uid, UpsertData,
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

#[derive(Default, Clone)]
pub struct FindexInMemory<const UID_LENGTH: usize> {
    entry_table: EncryptedTable<UID_LENGTH>,
    chain_table: EncryptedTable<UID_LENGTH>,
    removed_locations: HashSet<Location>,
    check_progress_callback_next_keyword: bool,
}

impl<const UID_LENGTH: usize> FindexInMemory<UID_LENGTH> {
    /// The entry table length (number of records)
    #[must_use]
    pub fn entry_table_len(&self) -> usize {
        self.entry_table.len()
    }

    /// The entry table size in bytes
    #[must_use]
    pub fn entry_table_size(&self) -> usize {
        let mut size = 0;
        for (k, v) in self.entry_table.iter() {
            size += k.len() + v.len();
        }
        size
    }

    /// The chain table length (number of records)
    #[must_use]
    pub fn chain_table_len(&self) -> usize {
        self.chain_table.len()
    }

    /// The entry table size in bytes
    #[must_use]
    pub fn chain_table_size(&self) -> usize {
        let mut size = 0;
        for (k, v) in self.chain_table.iter() {
            size += k.len() + v.len();
        }
        size
    }

    pub fn remove_location(&mut self, location: Location) {
        self.removed_locations.insert(location);
    }

    pub fn set_check_progress_callback_next_keyword(&mut self, value: bool) {
        self.check_progress_callback_next_keyword = value;
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
            let keyword = &Keyword::from("rob");
            let results = results
                .get(keyword)
                .ok_or_else(|| {
                    ExampleError(format!(
                        "Cannot find keyword {keyword:?} in search results {results:?}"
                    ))
                })
                .unwrap();
            assert!(results.contains(&IndexedValue::NextKeyword(Keyword::from("robert"))));
        }
        // do not stop recursion.
        Ok(true)
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, ExampleError> {
        let mut entry_table_items = EncryptedTable::default();
        for keyword_hash in entry_table_uids {
            if let Some(value) = self.entry_table.get(keyword_hash) {
                entry_table_items.insert(keyword_hash.clone(), value.clone());
            }
        }
        Ok(entry_table_items)
    }

    async fn fetch_chain_table(
        &self,
        chain_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, ExampleError> {
        Ok(chain_uids
            .iter()
            .filter_map(|uid| {
                self.chain_table
                    .get(uid)
                    .map(|value| (uid.clone(), value.clone()))
            })
            .collect::<HashMap<Uid<UID_LENGTH>, Vec<u8>>>()
            .into())
    }

    async fn upsert_entry_table(
        &mut self,
        modifications: &UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, ExampleError> {
        let mut rng = CsRng::from_entropy();
        let mut rejected = EncryptedTable::default();
        // Simulate insertion failures.
        for (uid, (old_value, new_value)) in modifications.iter() {
            // Reject insert with probability 0.2.
            if self.entry_table.contains_key(uid) && rng.gen_range(0..5) == 0 {
                rejected.insert(uid.clone(), old_value.clone().unwrap_or_default());
            } else {
                self.entry_table.insert(uid.clone(), new_value.clone());
            }
        }
        Ok(rejected)
    }

    async fn insert_chain_table(
        &mut self,
        items: &EncryptedTable<UID_LENGTH>,
    ) -> Result<(), ExampleError> {
        for (uid, value) in items.iter() {
            if self.chain_table.contains_key(uid) {
                return Err(ExampleError(format!(
                    "Conflict in Chain Table for UID: {uid:?}"
                )));
            }
            self.chain_table.insert(uid.clone(), value.clone());
        }
        Ok(())
    }

    fn update_lines(
        &mut self,
        chain_table_uids_to_remove: HashSet<Uid<UID_LENGTH>>,
        new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), ExampleError> {
        self.entry_table = EncryptedTable::default();

        for new_encrypted_entry_table_item in new_encrypted_entry_table_items.iter() {
            self.entry_table.insert(
                new_encrypted_entry_table_item.0.clone(),
                new_encrypted_entry_table_item.1.clone(),
            );
        }

        for new_encrypted_chain_table_item in new_encrypted_chain_table_items.iter() {
            self.chain_table.insert(
                new_encrypted_chain_table_item.0.clone(),
                new_encrypted_chain_table_item.1.clone(),
            );
        }

        for removed_chain_table_uid in chain_table_uids_to_remove {
            self.chain_table.remove(&removed_chain_table_uid);
        }

        Ok(())
    }

    fn list_removed_locations(
        &self,
        _: &HashSet<Location>,
    ) -> Result<HashSet<Location>, ExampleError> {
        Ok(self.removed_locations.iter().cloned().collect())
    }

    fn filter_removed_locations(
        &self,
        locations: &HashSet<Location>,
    ) -> Result<HashSet<Location>, ExampleError> {
        Ok(locations
            .iter()
            .filter(|location| !self.removed_locations.contains(location))
            .cloned()
            .collect())
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<HashSet<Uid<UID_LENGTH>>, ExampleError> {
        let uids: HashSet<Uid<UID_LENGTH>> = self.entry_table.keys().cloned().collect();
        Ok(uids)
    }

    async fn delete_chain(&mut self, uids: &HashSet<Uid<UID_LENGTH>>) -> Result<(), ExampleError> {
        self.chain_table.retain(|uid, _| !uids.contains(uid));
        Ok(())
    }
}

impl_findex_trait!(FindexSearch, FindexInMemory<UID_LENGTH>, ExampleError);

impl_findex_trait!(FindexUpsert, FindexInMemory<UID_LENGTH>, ExampleError);

impl_findex_trait!(FindexCompact, FindexInMemory<UID_LENGTH>, ExampleError);

#[cfg(feature = "live_compact")]
impl
    FindexLiveCompact<
        UID_LENGTH,
        BLOCK_LENGTH,
        CHAIN_TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
        ExampleError,
    > for FindexInMemory<UID_LENGTH>
{
    const BATCH_SIZE: usize = 10;
    const NOISE_RATIO: f64 = 0.5;
}
