use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
use rand::Rng;

use crate::{
    callbacks::FetchChains, parameters::UID_LENGTH, EncryptedTable, FindexCallbacks, FindexCompact,
    FindexSearch, FindexUpsert, IndexedValue, Keyword, Location, Uid, UpsertData,
};
#[cfg(feature = "live_compact")]
use crate::{compact_live::FindexLiveCompact, parameters::*};

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
    pub check_progress_callback_next_keyword: bool,
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
        // do not stop recursion.
        Ok(true)
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<HashSet<Uid<UID_LENGTH>>, ExampleError> {
        let uids = self.entry_table.keys().cloned().collect();
        Ok(uids)
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, ExampleError> {
        let mut items = EncryptedTable::with_capacity(entry_table_uids.len());
        for uid in entry_table_uids {
            if let Some(value) = self.entry_table.get(&uid) {
                items.insert(uid, value.clone());
            }
        }
        Ok(items)
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, ExampleError> {
        let mut items = EncryptedTable::with_capacity(chain_table_uids.len());
        for uid in chain_table_uids {
            if let Some(value) = self.chain_table.get(&uid) {
                items.insert(uid, value.clone());
            }
        }
        Ok(items)
    }

    async fn upsert_entry_table(
        &mut self,
        modifications: UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, ExampleError> {
        let mut rng = CsRng::from_entropy();
        let mut rejected = EncryptedTable::default();
        // Simulate insertion failures.
        for (uid, (old_value, new_value)) in modifications {
            // Reject insert with probability 0.2.
            if self.entry_table.contains_key(&uid) && rng.gen_range(0..5) == 0 {
                rejected.insert(uid, old_value.unwrap_or_default());
            } else {
                self.entry_table.insert(uid, new_value);
            }
        }
        Ok(rejected)
    }

    async fn insert_chain_table(
        &mut self,
        items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), ExampleError> {
        for (uid, value) in items {
            if self.chain_table.contains_key(&uid) {
                return Err(ExampleError(format!(
                    "Conflict in Chain Table for UID: {uid:?}"
                )));
            }
            self.chain_table.insert(uid, value);
        }
        Ok(())
    }

    fn update_lines(
        &mut self,
        chain_table_uids_to_remove: HashSet<Uid<UID_LENGTH>>,
        new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), ExampleError> {
        self.entry_table = new_encrypted_entry_table_items;

        for new_encrypted_chain_table_item in new_encrypted_chain_table_items {
            self.chain_table.insert(
                new_encrypted_chain_table_item.0,
                new_encrypted_chain_table_item.1,
            );
        }

        for removed_chain_table_uid in chain_table_uids_to_remove {
            self.chain_table.remove(&removed_chain_table_uid);
        }

        Ok(())
    }

    fn list_removed_locations(
        &self,
        _: HashSet<Location>,
    ) -> Result<HashSet<Location>, ExampleError> {
        Ok(self.removed_locations.iter().cloned().collect())
    }

    #[cfg(feature = "live_compact")]
    fn filter_removed_locations(
        &self,
        locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, ExampleError> {
        Ok(locations
            .into_iter()
            .filter(|location| !self.removed_locations.contains(location))
            .collect())
    }

    #[cfg(feature = "live_compact")]
    async fn delete_chain(&mut self, uids: HashSet<Uid<UID_LENGTH>>) -> Result<(), ExampleError> {
        self.chain_table.retain(|uid, _| !uids.contains(uid));
        Ok(())
    }
}

impl
    FetchChains<
        UID_LENGTH,
        BLOCK_LENGTH,
        CHAIN_TABLE_WIDTH,
        KWI_LENGTH,
        DEM_KEY_LENGTH,
        DemScheme,
        ExampleError,
    > for FindexInMemory<UID_LENGTH>
{
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
