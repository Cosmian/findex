//! This module defines the `FindexUpsert` trait. It is used to modify the
//! indexes.

use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::{
    reexport::rand_core::SeedableRng,
    symmetric_crypto::{Dem, SymKey},
    CsRng,
};

use crate::{
    entry_table::EntryTable,
    error::{CallbackError, Error},
    keys::KeyingMaterial,
    structs::{BlockType, EncryptedTable, IndexedValue, Keyword, Label, Uid, UpsertData},
    FindexCallbacks, ENTRY_TABLE_KEY_DERIVATION_INFO,
};

/// This the public trait exposed to the users of the Findex Upsert API.
pub trait FindexUpsert<
    const UID_LENGTH: usize,
    const BLOCK_LENGTH: usize,
    const CHAIN_TABLE_WIDTH: usize,
    const MASTER_KEY_LENGTH: usize,
    const KWI_LENGTH: usize,
    const KMAC_KEY_LENGTH: usize,
    const DEM_KEY_LENGTH: usize,
    KmacKey: SymKey<KMAC_KEY_LENGTH>,
    DemScheme: Dem<DEM_KEY_LENGTH>,
    CustomError: std::error::Error + CallbackError,
>: FindexCallbacks<CustomError, UID_LENGTH>
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
        additions: HashMap<IndexedValue, HashSet<Keyword>>,
        deletions: HashMap<IndexedValue, HashSet<Keyword>>,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
    ) -> Result<(), Error<CustomError>> {
        let mut rng = CsRng::from_entropy();

        // Revert the `HashMap`.
        let mut new_chain_elements =
            HashMap::<Keyword, HashMap<IndexedValue, BlockType>>::default();

        for (indexed_value, keywords) in additions {
            for keyword in keywords {
                new_chain_elements
                    .entry(keyword)
                    .or_default()
                    .insert(indexed_value.clone(), BlockType::Addition);
            }
        }

        // Adding and deleting the same indexed value for the same keyword only performs
        // the deletion.
        for (indexed_value, keywords) in deletions {
            for keyword in keywords {
                new_chain_elements
                    .entry(keyword)
                    .or_default()
                    .insert(indexed_value.clone(), BlockType::Deletion);
            }
        }

        // Derive DEM and KMAC keys.
        let k_uid: KmacKey = master_key.derive_kmac_key(ENTRY_TABLE_KEY_DERIVATION_INFO);
        let k_value = master_key.derive_dem_key(ENTRY_TABLE_KEY_DERIVATION_INFO);

        let keyword_to_entry_table_uid = new_chain_elements
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
            .fetch_entry_table(&keyword_to_entry_table_uid.values().cloned().collect())
            .await?;

        while !new_chain_elements.is_empty() {
            // Decrypt the Entry Table once and for all.
            let mut entry_table = EntryTable::<UID_LENGTH, KWI_LENGTH>::decrypt::<
                BLOCK_LENGTH,
                DEM_KEY_LENGTH,
                DemScheme,
            >(&k_value, &encrypted_entry_table)?;

            // Upsert keywords locally.
            let chain_table_additions = entry_table.upsert::<
                CHAIN_TABLE_WIDTH,
                BLOCK_LENGTH,
                KMAC_KEY_LENGTH,
                DEM_KEY_LENGTH,
                KmacKey,
                DemScheme,
            >(
                &mut rng,
                &new_chain_elements,
                &keyword_to_entry_table_uid,
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

            for (keyword, uid) in &keyword_to_entry_table_uid {
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
    ) -> Result<EncryptedTable<UID_LENGTH>, Error<CustomError>> {
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
