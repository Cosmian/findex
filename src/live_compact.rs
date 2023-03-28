#![allow(dead_code)]
#![allow(unused_variables)]

use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
};

use cosmian_crypto_core::{
    reexport::rand_core::{CryptoRngCore, SeedableRng},
    symmetric_crypto::{Dem, SymKey},
    CsRng,
};

use crate::{
    entry_table::{EntryTable, EntryTableValue},
    structs::BlockType,
    CallbackError, EncryptedTable, Error, FindexCallbacks, FindexSearch, IndexedValue,
    KeyingMaterial, Location, Uid, UpsertData, ENTRY_TABLE_KEY_DERIVATION_INFO,
};

pub trait FindexLiveCompact<
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
>:
    FindexCallbacks<CustomError, UID_LENGTH>
    + FindexSearch<
        UID_LENGTH,
        BLOCK_LENGTH,
        CHAIN_TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
        CustomError,
    >
{
    /// Ratio of the noise compared to the real data in percent.
    const NOISE_RATIO: usize = 50;

    /// Selects a set of Entry Table UIDs to reindex and a set of Entry Table
    /// UIDs used as noise.
    fn select_noisy_uids(
        &self,
    ) -> Result<(Vec<Uid<UID_LENGTH>>, HashSet<Uid<UID_LENGTH>>), Error<CustomError>> {
        todo!()
    }

    /// Fetch all useful information from the Chain Table for the compact
    /// operation:
    /// - the map of Entry Table UIDs to Chain Table UIDs
    /// - the map of Entry Table UIDs to indexed values
    ///
    /// # Paramters
    ///
    /// - `k_value`                 : DEM key used to decrypt the Entry Table
    /// - `encrypted_entry_table`   : encrypted Entry Table
    /// - `fetch_chains_batch_size` : number of chain UIDs to request at once
    async fn fetch_chain_data(
        &self,
        k_value: &DemScheme::Key,
        encrypted_entry_table: &EncryptedTable<UID_LENGTH>,
        fetch_chains_batch_size: NonZeroUsize,
    ) -> Result<
        (
            HashMap<Uid<UID_LENGTH>, Vec<Uid<UID_LENGTH>>>,
            HashMap<Uid<UID_LENGTH>, HashSet<IndexedValue>>,
        ),
        Error<CustomError>,
    > {
        // Decrypt entry table.
        let noisy_entry_table: EntryTable<UID_LENGTH, KWI_LENGTH> =
            EntryTable::decrypt::<DEM_KEY_LENGTH, DemScheme>(k_value, encrypted_entry_table)?;

        // Unchain all Entry Table UIDs.
        let kwi_chain_table_uids = noisy_entry_table.unchain::<
            CHAIN_TABLE_WIDTH,
            BLOCK_LENGTH,
            KMAC_KEY_LENGTH,
            DEM_KEY_LENGTH,
            KmacKey,
            DemScheme
        >(noisy_entry_table.keys(), usize::MAX);

        // Associate Entry UIDs to Chain UIDs.
        let noisy_chains = noisy_entry_table
            .iter()
            .map(|(uid, v)| {
                Ok((
                    uid.clone(),
                    kwi_chain_table_uids
                        .get(&v.kwi)
                        .ok_or(Error::<CustomError>::CryptoError(format!(
                            "No matching Kwi in `kwi_chain_table_uids` ({:?})",
                            v.kwi
                        )))?
                        .clone(),
                ))
            })
            .collect::<Result<HashMap<_, _>, Error<_>>>()?;

        // Fetch Chain Table for the given UIDs.
        let chains = self
            .noisy_fetch_chains(&kwi_chain_table_uids, fetch_chains_batch_size)
            .await?;

        // Convert the blocks of the given chains into indexed values.
        let mut noisy_indexed_values = HashMap::new();
        for (entry_table_uid, entry_table_value) in noisy_entry_table.iter() {
            let chain =
                chains
                    .get(&entry_table_value.kwi)
                    .ok_or(Error::<CustomError>::CryptoError(format!(
                        "No matching Kwi in `kwi_chain_table_uids` ({:?})",
                        entry_table_value.kwi
                    )))?;
            // TODO: use the same trick everywhere to avoid allocating (do not consume the
            // map of the chains to allow producing an iterator on references).
            let blocks = chain
                .iter()
                .flat_map(|(_, chain_table_value)| chain_table_value.as_blocks());
            noisy_indexed_values
                .insert(entry_table_uid.clone(), IndexedValue::from_blocks(blocks)?);
        }

        Ok((noisy_chains, noisy_indexed_values))
    }

    /// Updates noisy Entry Table entries and compacts chains associated to
    /// targeted entries.
    ///
    /// Returns the new Entry Table entries with noise entries unchanged, but
    /// updated `K_wi` and last UID value for the targeted ones, along with
    /// their associated encrypted and compacted Chain Table entries.
    ///
    /// # Paramaters
    ///
    /// - `rng`                         : secure random number generator
    /// - `noise`                       : Entry Table UIDs of the noise
    /// - `noisy_remaining_locations`   : remaining locations (contains noise)
    /// - `noisy_chains`                : row data to be compacted (contains
    ///   noise)
    fn compact_chains(
        &self,
        rng: &mut impl CryptoRngCore,
        k_value: &DemScheme::Key,
        noise: &HashSet<Uid<UID_LENGTH>>,
        noisy_remaining_locations: &HashSet<Location>,
        noisy_encrypted_entry_table: &EncryptedTable<UID_LENGTH>,
        noisy_chains: &HashMap<Uid<UID_LENGTH>, HashSet<IndexedValue>>,
    ) -> Result<
        (
            EntryTable<UID_LENGTH, KWI_LENGTH>,
            HashMap<Uid<UID_LENGTH>, EncryptedTable<UID_LENGTH>>,
        ),
        Error<CustomError>,
    > {
        //
        // Compute the new Entry Table and associated Chain Table entries.
        let mut noisy_entry_table = EntryTable::with_capacity(noisy_chains.len());
        let mut compacted_chains = HashMap::with_capacity(noisy_chains.len() - noise.len());
        let mut cache = HashMap::with_capacity(noisy_chains.len() - noise.len());

        for (uid, values) in noisy_chains {
            let entry_table_value = EntryTableValue::decrypt::<DEM_KEY_LENGTH, DemScheme>(
                k_value,
                &noisy_encrypted_entry_table.get(uid).cloned().ok_or(
                    Error::<CustomError>::CryptoError(
                        "No matching UID in the encrypted Entry Table".to_string(),
                    ),
                )?,
            )?;
            if noise.contains(uid) {
                // Noise entries are simply re-encrypted.
                noisy_entry_table.insert(uid.clone(), entry_table_value);
            } else {
                // Compact chains associated to the other entries.
                let mut compacted_chain = HashMap::with_capacity(values.len());
                for value in values {
                    match value {
                        IndexedValue::Location(location) => {
                            if noisy_remaining_locations.contains(location) {
                                compacted_chain.insert(
                                    IndexedValue::from(location.clone()),
                                    BlockType::Addition,
                                );
                            }
                        }
                        IndexedValue::NextKeyword(keyword) => {
                            // TODO: deal with obsolete `NextWord`s
                            compacted_chain
                                .insert(IndexedValue::from(keyword.clone()), BlockType::Addition);
                        }
                    };
                }
                cache.insert(entry_table_value.keyword_hash, uid.clone());
                compacted_chains.insert(entry_table_value.keyword_hash, compacted_chain);
            }
        }

        let compacted_chain_table = noisy_entry_table.upsert::<
            CHAIN_TABLE_WIDTH,
            BLOCK_LENGTH,
            KMAC_KEY_LENGTH,
            DEM_KEY_LENGTH,
            KmacKey,
            DemScheme
        >(rng, &compacted_chains, &cache)?;

        Ok((noisy_entry_table, compacted_chain_table))
    }

    /// Live compact the given UIDs.
    async fn live_compact_uids(
        &mut self,
        rng: &mut impl CryptoRngCore,
        k_value: &DemScheme::Key,
        noisy_uids: Vec<Uid<UID_LENGTH>>,
        noise: HashSet<Uid<UID_LENGTH>>,
        fetch_chains_batch_size: NonZeroUsize,
    ) -> Result<(), Error<CustomError>> {
        // Fetch all index entries (noisy).
        let mut noisy_encrypted_entry_table = self
            .fetch_entry_table(&HashSet::from_iter(noisy_uids.into_iter()))
            .await?;

        // Fetch chain data (noisy).
        let (noisy_chains, noisy_indexed_values) = self
            .fetch_chain_data(
                k_value,
                &noisy_encrypted_entry_table,
                fetch_chains_batch_size,
            )
            .await?;

        // Select remaining locations (noisy).
        let noisy_locations: HashSet<Location> = noisy_indexed_values
            .iter()
            .flat_map(|(_, values)| values)
            .filter_map(|value| value.get_location())
            .cloned()
            .collect();
        let noisy_remaining_locations = self.filter_removed_locations(&noisy_locations)?;

        // While there are some Entry Table elements to compact...
        while !noisy_encrypted_entry_table.is_empty() {
            // Compute the new Entry Table (noisy) and compact chains (not noisy).
            let (noisy_entry_table, new_chains) = self.compact_chains(
                rng,
                k_value,
                &noise,
                &noisy_remaining_locations,
                &noisy_encrypted_entry_table,
                &noisy_indexed_values,
            )?;

            // Insert all recompacted chains first.
            let chain_table = new_chains.iter().flat_map(|(k, v)| v.clone()).collect();
            self.insert_chain_table(&chain_table).await?;

            // Try upserting the new entry table.
            let upsert_data = UpsertData::new(
                &noisy_encrypted_entry_table,
                noisy_entry_table.encrypt::<DEM_KEY_LENGTH, DemScheme>(k_value, rng)?,
            );

            // These are failures to upsert.
            noisy_encrypted_entry_table = self.upsert_entry_table(&upsert_data).await?;

            // Delete unused chains (at least one chain element per upsert try):
            let mut chains_to_delete: HashSet<Uid<UID_LENGTH>> =
                HashSet::with_capacity(upsert_data.len());
            // - new chains corresponding to unsuccessful upserts
            chains_to_delete.extend(
                new_chains
                    .iter()
                    .filter_map(|(uid, chains)| {
                        if noisy_encrypted_entry_table.contains_key(uid) {
                            Some(chains.keys())
                        } else {
                            None
                        }
                    })
                    .flatten()
                    .cloned(),
            );

            // - old chains corresponding to successful upserts
            chains_to_delete.extend(
                noisy_chains
                    .iter()
                    .filter_map(|(uid, chain)| {
                        if !noisy_encrypted_entry_table.contains_key(uid) && !noise.contains(uid) {
                            Some(chain)
                        } else {
                            None
                        }
                    })
                    .flatten()
                    .cloned(),
            );
        }

        Ok(())
    }

    /// Live compact algorithm.
    ///
    /// See notion for an explanation and analysis.
    async fn live_compact(
        &mut self,
        key: KeyingMaterial<MASTER_KEY_LENGTH>,
        fetch_chains_batch_size: NonZeroUsize,
    ) -> Result<(), Error<CustomError>> {
        let mut rng = CsRng::from_entropy();

        let k_value =
            key.derive_dem_key::<DEM_KEY_LENGTH, DemScheme::Key>(ENTRY_TABLE_KEY_DERIVATION_INFO);

        // Select a fraction of the Entry Table to reindex (noisy).
        let (noisy_entry_table_uids, noise) = self.select_noisy_uids()?;

        // TODO: Here loop on batch of UIDS.
        self.live_compact_uids(
            &mut rng,
            &k_value,
            noisy_entry_table_uids,
            noise,
            fetch_chains_batch_size,
        )
        .await?;

        Ok(())
    }
}
