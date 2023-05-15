//! This module defines the `FindexUpsert` trait. It is used to modify the
//! indexes.

use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng,
    symmetric_crypto::{Dem, SymKey},
    CsRng,
};

use crate::{
    core::{
        entry_table::EntryTable,
        keys::KeyingMaterial,
        structs::{EncryptedTable, IndexedValue, Keyword, Label, Uid, UpsertData},
        FindexCallbacks, ENTRY_TABLE_KEY_DERIVATION_INFO,
    },
    error::FindexErr,
};

/// This the public trait exposed to the users of the Findex Upsert API.
pub trait FindexUpsert<
    const UID_LENGTH: usize,
    const BLOCK_LENGTH: usize,
    const TABLE_WIDTH: usize,
    const MASTER_KEY_LENGTH: usize,
    const KWI_LENGTH: usize,
    const KMAC_KEY_LENGTH: usize,
    const DEM_KEY_LENGTH: usize,
    KmacKey: SymKey<KMAC_KEY_LENGTH>,
    DemScheme: Dem<DEM_KEY_LENGTH>,
>: FindexCallbacks<UID_LENGTH>
{
    /// Index the given values for the given keywords. After upserting, any
    /// search for such a keyword will result in finding (at least) the
    /// corresponding value.
    ///
    /// # Parameters
    ///
    /// - `new_chain_elements`  : values to index by keywords
    /// - `master_key`          : Findex master key
    /// - `label`               : additional public information used for hashing
    ///   Entry Table UIDs
    async fn upsert(
        &mut self,
        indexed_value_to_keywords: HashMap<IndexedValue, HashSet<Keyword>>,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
    ) -> Result<(), FindexErr> {
        let mut rng = CsRng::from_entropy();

        // Revert the `HashMap`.
        let mut new_chain_elements = HashMap::<Keyword, HashSet<IndexedValue>>::default();
        for (indexed_value, keywords) in indexed_value_to_keywords {
            for keyword in keywords {
                new_chain_elements
                    .entry(keyword)
                    .or_default()
                    .insert(indexed_value.clone());
            }
        }

        // Derive DEM and KMAC keys.
        let k_uid: KmacKey = master_key.derive_kmac_key(ENTRY_TABLE_KEY_DERIVATION_INFO);
        let k_value = master_key.derive_dem_key(ENTRY_TABLE_KEY_DERIVATION_INFO);

        // Get the list of keywords to upsert with their associated Entry Table UID.
        let entry_table_uid_cache = new_chain_elements
            .keys()
            .map(|keyword| {
                (
                    keyword.clone(),
                    EntryTable::<UID_LENGTH, KWI_LENGTH>::generate_uid(
                        &k_uid,
                        &keyword.hash(),
                        label,
                    ),
                )
            })
            .collect::<HashMap<_, _>>();

        // Query the Entry Table for these UIDs.
        let mut encrypted_entry_table = self
            .fetch_entry_table(&entry_table_uid_cache.values().cloned().collect())
            .await?
            .to_encrypted_table()?;

        while !new_chain_elements.is_empty() {
            // Decrypt the Entry Table once and for all.
            let mut entry_table = EntryTable::<UID_LENGTH, KWI_LENGTH>::decrypt::<
                BLOCK_LENGTH,
                DEM_KEY_LENGTH,
                DemScheme,
            >(&k_value, &encrypted_entry_table)?;

            // Upsert keywords locally.
            let chain_table_additions = entry_table.upsert::<
                BLOCK_LENGTH,
                TABLE_WIDTH,
                KMAC_KEY_LENGTH,
                DEM_KEY_LENGTH,
                KmacKey,
                DemScheme,
            >(
                &mut rng,
                &new_chain_elements,
                &entry_table_uid_cache,
            )?;

            // Finally write new indexes in database. Get the new values of the Entry Table
            // lines that failed to be upserted.
            encrypted_entry_table = self
                .write_indexes(
                    encrypted_entry_table,
                    entry_table
                        .encrypt::<BLOCK_LENGTH, DEM_KEY_LENGTH, DemScheme>(&k_value, &mut rng)?,
                    chain_table_additions,
                )
                .await?;

            for (keyword, uid) in &entry_table_uid_cache {
                // Remove chains that have successfully been upserted.
                if !encrypted_entry_table.contains_key(uid) {
                    new_chain_elements.remove_entry(keyword);
                }
            }
        }
        Ok(())
    }

    /// Writes the given modifications to the indexes. Returns the current value
    /// in the Entry Table for the lines that could not be upserted (cf
    /// `upsert_entry_table()`).
    ///
    /// - `old_entry_table`         : old Entry Table
    /// - `new_entry_table`         : new Entry Table
    /// - `chain_table_additions`   : entries to be added to the Chain Table
    async fn write_indexes(
        &mut self,
        old_entry_table: EncryptedTable<UID_LENGTH>,
        new_entry_table: EncryptedTable<UID_LENGTH>,
        mut chain_table_additions: HashMap<Uid<UID_LENGTH>, EncryptedTable<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr> {
        // Convert old and new Entry Tables to the correct format.
        let entry_table_modifications = UpsertData::new(&old_entry_table, new_entry_table);

        // Try upserting Entry Table modifications. Get the current values of the Entry
        // Table lines that failed to be upserted.
        let encrypted_entry_table = self.upsert_entry_table(&entry_table_modifications).await?;

        // Insert new Chain Table lines.
        chain_table_additions.retain(|uid, _| !encrypted_entry_table.contains_key(uid));
        let new_chain_table_entries = chain_table_additions.into_values().flatten().collect();

        self.insert_chain_table(&new_chain_table_entries).await?;

        Ok(encrypted_entry_table)
    }
}
