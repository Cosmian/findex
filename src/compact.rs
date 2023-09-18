//! This module defines the `FindexCompact` trait.

use std::collections::HashMap;

use async_trait::async_trait;
use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
use rand::seq::IteratorRandom;

use crate::{
    callbacks::FetchChains,
    chain_table::{ChainTable, KwiChainUids},
    entry_table::{EntryTable, EntryTableValue},
    error::CallbackError,
    parameters::check_parameter_constraints,
    structs::{BlockType, EncryptedTable, IndexedValue, Label},
    Error, FindexCallbacks, KeyingMaterial, Uids, CHAIN_TABLE_KEY_DERIVATION_INFO,
    ENTRY_TABLE_KEY_DERIVATION_INFO,
};

/// The compact operation is required to remove old indexes from the Index
/// Chain Table and to improve the security of the index by changing all the
/// Index Entry Table.
#[async_trait(?Send)]
pub trait FindexCompact<
    const UID_LENGTH: usize,
    const BLOCK_LENGTH: usize,
    const CHAIN_TABLE_WIDTH: usize,
    const MASTER_KEY_LENGTH: usize,
    const KWI_LENGTH: usize,
    const KMAC_KEY_LENGTH: usize,
    CustomError: std::error::Error + CallbackError,
>:
    FindexCallbacks<CustomError, UID_LENGTH>
    + FetchChains<UID_LENGTH, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KWI_LENGTH, CustomError>
{
    /// Replaces all the Index Entry Table UIDs and values. New UIDs are derived
    /// using the given label and the KMAC key derived from the new master key.
    /// The values are decrypted using the DEM key derived from the master key
    /// and re-encrypted using the DEM key derived from the new master key.
    ///
    /// Randomly selects index entries and recompact their associated chains.
    /// Chains indexing no existing location are removed. Others are recomputed
    /// from a new keying material. This removes unneeded paddings. New UIDs are
    /// derived for the chain and values are re-encrypted using a DEM key
    /// derived from the new keying material.
    ///
    /// - `master_key`                      : master key used to generate the
    ///   current index
    /// - `new_master_key`                  : master key used to generate the
    ///   new index
    /// - `label`                           : label used to generate the new
    ///   index
    /// - `num_reindexing_before_full_set`  : average number of calls to compact
    ///   needed to recompute all of the Chain Table.
    ///
    /// **WARNING**: the compact operation *cannot* be done concurrently with
    /// upsert operations. This could result in corrupted indexes.
    async fn compact(
        &self,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        new_master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
        num_reindexing_before_full_set: u32,
    ) -> Result<(), Error<CustomError>> {
        check_parameter_constraints::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH>();
        if num_reindexing_before_full_set == 0 {
            return Err(Error::CryptoError(
                "`num_reindexing_before_full_set` cannot be 0.".to_owned(),
            ));
        }

        let mut rng = CsRng::from_entropy();

        //
        // Derive the keys used to encrypt/decrypt the Entry Table.
        // Decrypt using `k_value`, generate new UIDs using `new_k_uid` and encrypt
        // using `new_k_value`.
        //
        let k_value = master_key.derive_dem_key(ENTRY_TABLE_KEY_DERIVATION_INFO);
        let new_k_uid =
            new_master_key.derive_kmac_key::<KMAC_KEY_LENGTH>(ENTRY_TABLE_KEY_DERIVATION_INFO);
        let new_k_value = new_master_key.derive_dem_key(ENTRY_TABLE_KEY_DERIVATION_INFO);

        // We need to fetch all the Entry Table to re-encrypt it.
        // First, fetch all UIds of the Entry table
        let all_uids = self.fetch_all_entry_table_uids().await?;
        let encrypted_entry_table = self.fetch_entry_table(all_uids).await?.try_into()?;

        // The goal of this function is to build these two data sets (along with
        // `chain_table_uids_to_remove`) and send them to the callback to update the
        // database.
        let mut entry_table = EntryTable::decrypt(&k_value, &encrypted_entry_table)?;
        let mut chain_table_adds = EncryptedTable::default();

        // Entry Table items indexing empty chains should be removed.
        let mut entry_table_uids_to_drop = Vec::new();

        // Randomly select `n_lines` Entry Table lines such that an average number of
        // `num_reindexing_before_full_set` calls to `compact` are needed to compact all
        // the chain table.  See `documentation/Findex.pdf` and coupon problem to
        // understand this formula.
        let entry_table_length = entry_table.len() as f64;
        let n_lines = ((entry_table_length * (entry_table_length.log2() + 0.58))
            / f64::from(num_reindexing_before_full_set))
        .ceil() as usize;
        let entry_table_items_to_reindex = entry_table
            .keys()
            .choose_multiple(&mut rng, n_lines)
            .into_iter()
            .copied()
            .collect::<Vec<_>>();

        // Unchain the Entry Table entries to be reindexed.
        let mut kwi_chain_table_uids =
            KwiChainUids::<UID_LENGTH, KWI_LENGTH>::with_capacity(entry_table.len());
        for (uid, value) in entry_table.iter() {
            if entry_table_items_to_reindex.contains(uid) {
                let k_uid = value
                    .kwi
                    .derive_kmac_key::<KMAC_KEY_LENGTH>(CHAIN_TABLE_KEY_DERIVATION_INFO);
                let chain =
                    value.unchain::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH, KMAC_KEY_LENGTH>(&k_uid)?;
                kwi_chain_table_uids.insert(value.kwi.clone(), chain);
            }
        }

        //
        // Batch fetch chains from the Chain Table. It's better for performances and
        // prevents the database. There is no way for the database to know which Entry
        // Table lines are linked to the requested UIDs since the Entry Table was fetch
        // entirely and a random portion of it is being compacted.
        //
        let chains_to_reindex = self.fetch_chains(kwi_chain_table_uids).await?;

        //
        // Remove all reindexed Chain Table items. Chains are recomputed entirely.
        //
        let chain_table_uids_to_remove = Uids(
            chains_to_reindex
                .values()
                .flat_map(|chain| chain.iter().map(|(k, _)| k))
                .copied()
                .collect(),
        );

        // Get the values stored in the reindexed chains.
        let mut reindexed_chain_values = HashMap::with_capacity(chains_to_reindex.len());
        for (kwi, chain) in &chains_to_reindex {
            let blocks = chain
                .iter()
                .flat_map(|(_, chain_value)| chain_value.as_blocks());
            reindexed_chain_values.insert(kwi.clone(), IndexedValue::from_blocks(blocks)?);
        }

        //
        // Call `list_removed_locations` for all words in one pass instead of
        // calling for one location batch for one word to add noise and prevent
        // the database the size of the chains for each keywords.
        //
        let removed_locations = self
            .list_removed_locations(
                reindexed_chain_values
                    .values()
                    .flat_map(|chain| chain.iter().filter_map(IndexedValue::get_location))
                    .cloned()
                    .collect(),
            )
            .await?;

        for entry_table_uid in entry_table_items_to_reindex {
            let entry_table_value = entry_table.get(&entry_table_uid).ok_or_else(|| {
                Error::<CustomError>::CryptoError(format!(
                    "No match in the Entry Table for UID: {entry_table_uid:?}"
                ))
            })?;

            // Select all values indexed by this keyword.
            let indexed_values_for_this_keyword = reindexed_chain_values
                .get(&entry_table_value.kwi)
                .ok_or_else(|| {
                    Error::<CustomError>::CryptoError(format!(
                        "Unknown kwi: {:?}",
                        &entry_table_value.kwi
                    ))
                })?;

            // Filter out the values removed from the DB.
            //
            // TODO (TBZ): `NextWord`s should be managed here
            let remaining_indexed_values_for_this_keyword = indexed_values_for_this_keyword
                .iter()
                .filter(|indexed_value| {
                    !(indexed_value.is_location()
                        && removed_locations.contains(indexed_value.get_location().unwrap()))
                })
                .cloned()
                .collect::<Vec<_>>();

            if remaining_indexed_values_for_this_keyword.is_empty() {
                // All values indexed by this keyword have been removed.
                entry_table_uids_to_drop.push(entry_table_uid);
                continue;
            }

            // Start a new chain from scratch.
            let mut new_entry_table_value = EntryTableValue::<UID_LENGTH, KWI_LENGTH>::new::<
                CHAIN_TABLE_WIDTH,
                BLOCK_LENGTH,
            >(&mut rng, entry_table_value.keyword_hash);

            // Derive the new keys.
            let kwi_uid = new_entry_table_value
                .kwi
                .derive_kmac_key::<KMAC_KEY_LENGTH>(CHAIN_TABLE_KEY_DERIVATION_INFO);
            let kwi_value = new_entry_table_value
                .kwi
                .derive_dem_key(CHAIN_TABLE_KEY_DERIVATION_INFO);

            let mut new_chains = ChainTable::default();

            // Upsert each remaining location in the Chain Table.
            for remaining_location in remaining_indexed_values_for_this_keyword {
                new_entry_table_value
                    .upsert_indexed_value::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH, KMAC_KEY_LENGTH>(
                        &kwi_uid,
                        BlockType::Addition,
                        &remaining_location,
                        &mut new_chains,
                    )?;
            }

            let encrypted_new_chains = new_chains
                .into_iter()
                .map(|(uid, value)| -> Result<_, _> {
                    Ok((uid, value.encrypt(&mut rng, &kwi_value)?))
                })
                .collect::<Result<EncryptedTable<UID_LENGTH>, Error<CustomError>>>()?;

            chain_table_adds.extend(encrypted_new_chains);
            entry_table.insert(entry_table_uid, new_entry_table_value);
        }

        entry_table.retain(|uid, _| !entry_table_uids_to_drop.contains(uid));
        entry_table.refresh_uids::<KMAC_KEY_LENGTH>(&new_k_uid, label);

        self.update_lines(
            chain_table_uids_to_remove,
            entry_table.encrypt(&mut rng, &new_k_value)?,
            chain_table_adds,
        )
        .await?;

        Ok(())
    }
}
