//! This module defines the `FindexUpsert` trait. It is used to modify the
//! indexes.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};

use crate::{
    entry_table::EntryTable,
    error::{CallbackError, Error},
    keys::KeyingMaterial,
    parameters::check_parameter_constraints,
    structs::{BlockType, EncryptedTable, IndexedValue, Keyword, Label, Uid, UpsertData},
    FindexCallbacks, Uids, ENTRY_TABLE_KEY_DERIVATION_INFO,
};

/// This the public trait exposed to the users of the Findex Upsert API.
#[async_trait]
pub trait FindexUpsert<
    const UID_LENGTH: usize,
    const BLOCK_LENGTH: usize,
    const CHAIN_TABLE_WIDTH: usize,
    const MASTER_KEY_LENGTH: usize,
    const KWI_LENGTH: usize,
    const KMAC_KEY_LENGTH: usize,
    CustomError: std::error::Error + CallbackError,
>: FindexCallbacks<CustomError, UID_LENGTH>
{
    /// Index the given values for the associated keywords.
    ///
    /// Returns the set of the new keywords added.
    ///
    /// # Parameters
    ///
    /// - `master_key`  : Findex master key
    /// - `label`       : additional public information used in key hashing
    /// - `items`       : set of keywords used to index values
    async fn add(
        &self,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
        items: HashMap<IndexedValue, HashSet<Keyword>>,
    ) -> Result<HashSet<Keyword>, Error<CustomError>> {
        self.upsert(master_key, label, items, HashMap::new()).await
    }

    /// Removes the given values from the indexes for the associated keywords.
    ///
    /// This call actually adds a "delete" to the chain table
    /// (and potentially the Entry Table if it did not exits before)
    ///
    /// Returns the set of the new keywords added.
    ///
    /// # Parameters
    ///
    /// - `master_key`  : Findex master key
    /// - `label`       : additional public information used in key hashing
    /// - `items`       : set of keywords used to index values
    async fn remove(
        &self,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
        items: HashMap<IndexedValue, HashSet<Keyword>>,
    ) -> Result<HashSet<Keyword>, Error<CustomError>> {
        self.upsert(master_key, label, HashMap::new(), items).await
    }

    /// Upsert the given chain elements in Findex tables.
    ///
    /// Returns the set of the new keywords added.
    ///
    /// # Parameters
    ///
    /// - `master_key`  : Findex master key
    /// - `label`       : additional public information used in key hashing
    /// - `additions`   : values to indexed for a set of keywords
    /// - `deletions`   : values to remove from the indexes for a set of
    ///   keywords
    async fn upsert(
        &self,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
        additions: HashMap<IndexedValue, HashSet<Keyword>>,
        deletions: HashMap<IndexedValue, HashSet<Keyword>>,
    ) -> Result<HashSet<Keyword>, Error<CustomError>> {
        check_parameter_constraints::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH>();

        let mut rng = CsRng::from_entropy();
        let k_uid = master_key.derive_kmac_key::<KMAC_KEY_LENGTH>(ENTRY_TABLE_KEY_DERIVATION_INFO);
        let k_value = master_key.derive_dem_key(ENTRY_TABLE_KEY_DERIVATION_INFO);

        let mut modifications = HashMap::<Keyword, HashMap<IndexedValue, BlockType>>::with_capacity(
            additions.len() + deletions.len(),
        );
        for (indexed_value, keywords) in additions {
            for keyword in keywords {
                modifications
                    .entry(keyword)
                    .or_default()
                    .insert(indexed_value.clone(), BlockType::Addition);
            }
        }
        for (indexed_value, keywords) in deletions {
            for keyword in keywords {
                modifications
                    .entry(keyword)
                    .or_default()
                    .insert(indexed_value.clone(), BlockType::Deletion);
            }
        }

        let mut uid_to_keyword = HashMap::with_capacity(modifications.len());
        let mut new_chains = HashMap::with_capacity(modifications.len());
        for (keyword, indexed_values) in modifications {
            let keyword_hash = keyword.hash();
            let uid = EntryTable::<UID_LENGTH, KWI_LENGTH>::generate_uid::<KMAC_KEY_LENGTH>(
                &k_uid,
                &keyword_hash,
                label,
            );
            uid_to_keyword.insert(uid, keyword);
            new_chains.insert(uid, (keyword_hash, indexed_values));
        }

        // Query the Entry Table for these UIDs.
        let mut encrypted_entry_table: EncryptedTable<UID_LENGTH> = self
            .fetch_entry_table(Uids(new_chains.keys().copied().collect()))
            .await?
            .try_into()?;

        let new_keywords = uid_to_keyword
            .into_iter()
            .filter(|(uid, _)| !encrypted_entry_table.contains_key(uid))
            .map(|(_, keyword)| keyword)
            .collect();

        while !new_chains.is_empty() {
            // Decrypt the Entry Table once and for all.
            let mut entry_table =
                EntryTable::<UID_LENGTH, KWI_LENGTH>::decrypt(&k_value, &encrypted_entry_table)?;

            // Build the chains and update the Entry Table.
            let chain_table_additions = entry_table
                .upsert::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH, KMAC_KEY_LENGTH>(
                    &mut rng,
                    &new_chains,
                )?;

            // Finally write new indexes in database. Get the new values of the Entry Table
            // lines that failed to be upserted.
            encrypted_entry_table = self
                .write_indexes(
                    encrypted_entry_table,
                    entry_table.encrypt(&mut rng, &k_value)?,
                    chain_table_additions,
                )
                .await?;

            // Remove chains that have successfully been upserted.
            new_chains.retain(|uid, _| encrypted_entry_table.contains_key(uid));
        }

        Ok(new_keywords)
    }

    /// Writes the given modifications to the indexes. Returns the current value
    /// in the Entry Table for the lines that could not be upserted (cf
    /// `upsert_entry_table()`).
    ///
    /// - `old_entry_table`         : old Entry Table
    /// - `new_entry_table`         : new Entry Table
    /// - `chain_table_additions`   : entries to be added to the Chain Table
    async fn write_indexes(
        &self,
        old_entry_table: EncryptedTable<UID_LENGTH>,
        new_entry_table: EncryptedTable<UID_LENGTH>,
        mut chain_table_additions: HashMap<Uid<UID_LENGTH>, EncryptedTable<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, Error<CustomError>> {
        // Convert old and new Entry Tables to the correct format.
        let entry_table_modifications = UpsertData::new(&old_entry_table, new_entry_table);

        // Try upserting Entry Table modifications. Get the current values of the Entry
        // Table lines that failed to be upserted.
        let encrypted_entry_table = self.upsert_entry_table(entry_table_modifications).await?;

        // Insert new Chain Table lines.
        chain_table_additions.retain(|uid, _| !encrypted_entry_table.contains_key(uid));
        let new_chain_table_entries = chain_table_additions.into_values().flatten().collect();

        self.insert_chain_table(new_chain_table_entries).await?;

        Ok(encrypted_entry_table)
    }
}
