//! This module defines the `FindexCompact` trait.

use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::{
    bytes_ser_de::Serializable,
    reexport::rand_core::SeedableRng,
    symmetric_crypto::{Dem, SymKey},
    CsRng,
};
use rand::seq::IteratorRandom;

use super::FindexCallbacks;
use crate::{
    core::{
        chain_table::{ChainTableValue, KwiChainUids},
        entry_table::{EntryTable, EntryTableValue},
        structs::{Block, EncryptedTable, IndexedValue, Label, Uid},
        KeyingMaterial, CHAIN_TABLE_KEY_DERIVATION_INFO, ENTRY_TABLE_KEY_DERIVATION_INFO,
    },
    error::FindexErr,
};

/// The compact is an operation required to remove old indexes from the Index
/// Chain Table and to improve the security of the index by changing all the
/// Index Entry Table.
pub trait FindexCompact<
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
    /// Replaces all the Index Entry Table UIDs and values. New UIDs are derived
    /// using the given label and the KMAC key derived from the new master key.
    /// The values are dectypted using the DEM key derived from the master key
    /// and re-encrypted using the DEM key derived from the new master key.
    ///
    /// Randomly selects index entries and recompact their associated chains.
    /// Chains indexing no existing location are removed. Others are recomputed
    /// from a new keying material. This removes unneeded paddings. New UIDs are
    /// derived for the chain and values are re-encrypted using a DEM key
    /// derived from the new keying material.
    ///
    /// - `num_reindexing_before_full_set`  : average number of calls to compact
    ///   needed to recompute all of the Chain Table.
    /// - `master_key`                      : master key used to generate the
    ///   current index
    /// - `new_master_key`                  : master key used to generate the
    ///   new index
    /// - `label`                           : label used to generate the new
    ///   index
    ///
    /// **WARNING**: the compact operation *cannot* be done concurrently with
    /// upsert operations. This could result in corrupted indexes.
    async fn compact(
        &mut self,
        num_reindexing_before_full_set: u32,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        new_master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
    ) -> Result<(), FindexErr> {
        if num_reindexing_before_full_set == 0 {
            return Err(FindexErr::CryptoError(
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
        let new_k_uid = new_master_key.derive_kmac_key(ENTRY_TABLE_KEY_DERIVATION_INFO);
        let new_k_value = new_master_key.derive_dem_key(ENTRY_TABLE_KEY_DERIVATION_INFO);

        // We need to fetch all the Entry Table to re-encrypt it.
        let encrypted_entry_table = self.fetch_entry_table(None).await?;

        // The goal of this function is to build these two data sets (along with
        // `chain_table_uids_to_remove`) and send them to the callback to update the
        // database.
        let mut chain_table_adds = EncryptedTable::default();
        let mut entry_table = EntryTable::decrypt::<BLOCK_LENGTH, DEM_KEY_LENGTH, DemScheme>(
            &k_value,
            &encrypted_entry_table,
        )?;
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
            .cloned()
            .collect::<Vec<_>>();

        // Unchain the Entry Table entries to be reindexed.
        let kwi_chain_table_uids = entry_table
            .unchain::<BLOCK_LENGTH, KMAC_KEY_LENGTH, DEM_KEY_LENGTH, KmacKey, DemScheme>(
                entry_table_items_to_reindex.iter(),
                usize::MAX,
            );

        //
        // Batch fetch chains from the Chain Table. It's better for performances and
        // prevents the database. There is no way for the database to know which Entry
        // Table lines are linked to the requested UIDs since the Entry Table was fetch
        // entirely and a random portion of it is being compacted.
        //
        let chains_to_reindex = self.batch_fetch_chains(&kwi_chain_table_uids).await?;

        //
        // Remove all reindexed Chain Table items. Chains are recomputed entirely.
        //
        let chain_table_uids_to_remove = chains_to_reindex
            .values()
            .flat_map(|chain| chain.iter().map(|(k, _)| k))
            .cloned()
            .collect::<HashSet<_>>();

        // Get the values stored in the reindexed chains.
        let mut reindexed_chain_values = HashMap::with_capacity(chains_to_reindex.len());
        for (kwi, chain) in chains_to_reindex {
            let mut indexed_values = HashSet::new();
            let blocks = chain.into_iter().flat_map(|(_, v)| v).collect::<Vec<_>>();
            for bytes in Block::unpad(&blocks)? {
                indexed_values.insert(IndexedValue::try_from_bytes(&bytes)?);
            }
            reindexed_chain_values.insert(kwi.clone(), indexed_values);
        }

        //
        // Call `list_removed_locations` for all words in one pass instead of
        // calling for one location batch for one word to add noise and prevent
        // the database the size of the chains for each keywords.
        //
        let removed_locations = self.list_removed_locations(
            &reindexed_chain_values
                .values()
                .flat_map(|chain| chain.iter().filter_map(IndexedValue::get_location))
                .cloned()
                .collect(),
        )?;

        for entry_table_uid in entry_table_items_to_reindex {
            let entry_table_value = entry_table.get(&entry_table_uid).ok_or_else(|| {
                FindexErr::CryptoError(format!(
                    "No match in the Entry Table for UID: {entry_table_uid:?}"
                ))
            })?;

            // Select all values indexed by this keyword.
            let indexed_values_for_this_keyword = reindexed_chain_values
                .get(&entry_table_value.kwi)
                .ok_or_else(|| {
                    FindexErr::CryptoError(format!("Unknown kwi: {:?}", &entry_table_value.kwi))
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
                BLOCK_LENGTH,
                KMAC_KEY_LENGTH,
                KmacKey,
            >(&mut rng, entry_table_value.keyword_hash);

            // Derive the new keys.
            let kwi_uid = new_entry_table_value
                .kwi
                .derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);
            let kwi_value = new_entry_table_value
                .kwi
                .derive_dem_key(CHAIN_TABLE_KEY_DERIVATION_INFO);

            // Upsert each remaining location in the Chain Table.
            for remaining_location in remaining_indexed_values_for_this_keyword {
                new_entry_table_value.upsert_indexed_value::<BLOCK_LENGTH, TABLE_WIDTH, KMAC_KEY_LENGTH, DEM_KEY_LENGTH, KmacKey, DemScheme>(
                    &remaining_location,
                    &kwi_uid,
                    &kwi_value,
                    &mut chain_table_adds,
                    &mut rng,
                )?;
            }

            entry_table.insert(entry_table_uid.clone(), new_entry_table_value);
        }

        entry_table.retain(|uid, _| !entry_table_uids_to_drop.contains(uid));
        entry_table.refresh_uids::<KMAC_KEY_LENGTH, KmacKey>(&new_k_uid, label);

        // Call the callback
        self.update_lines(
            chain_table_uids_to_remove,
            entry_table
                .encrypt::<BLOCK_LENGTH, DEM_KEY_LENGTH, DemScheme>(&new_k_value, &mut rng)?,
            chain_table_adds,
        )?;

        Ok(())
    }

    /// Batch fetches the Chain Table values of the given chain UIDs.
    ///
    /// **WARNING**: there is no guarantee the server cannot link the Chain
    /// Table request to a previous Entry Table request.
    ///
    /// - `kwi_chain_table_uids`    : maps `Kwi`s to chains
    async fn batch_fetch_chains(
        &self,
        kwi_chain_table_uids: &KwiChainUids<UID_LENGTH, KWI_LENGTH>,
    ) -> Result<
        HashMap<KeyingMaterial<KWI_LENGTH>, Vec<(Uid<UID_LENGTH>, ChainTableValue<BLOCK_LENGTH>)>>,
        FindexErr,
    > {
        let chain_table_uids = kwi_chain_table_uids
            .values()
            .flatten()
            .cloned()
            .collect::<HashSet<_>>();

        // Batch fetch the server.
        let encrypted_chain_table_items = self.fetch_chain_table(&chain_table_uids).await?;

        // Reconsitute the chains.
        let mut chains = HashMap::with_capacity(kwi_chain_table_uids.len());
        for (kwi, chain_table_uids) in kwi_chain_table_uids.iter() {
            let kwi_value = kwi.derive_dem_key(CHAIN_TABLE_KEY_DERIVATION_INFO);
            let mut chain = Vec::with_capacity(chain_table_uids.len());
            for uid in chain_table_uids {
                let encrypted_item = encrypted_chain_table_items.get(uid).ok_or_else(|| {
                    FindexErr::CryptoError(format!(
                        "Chain UID does not exist in Chain Table: {uid:?}",
                    ))
                })?;
                // Use a vector not to shuffle the chain. This is important because indexed
                // values can be divided in blocks that span several lines in the chain.
                chain.push((
                    uid.clone(),
                    ChainTableValue::<BLOCK_LENGTH>::decrypt::<
                        TABLE_WIDTH,
                        DEM_KEY_LENGTH,
                        DemScheme,
                    >(&kwi_value, encrypted_item)?,
                ));
            }
            chains.insert(kwi.clone(), chain);
        }

        Ok(chains)
    }
}
