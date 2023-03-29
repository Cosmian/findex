//! Defines the live compact trait.

use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::{
    reexport::rand_core::{CryptoRngCore, SeedableRng},
    symmetric_crypto::{Dem, SymKey},
    CsRng,
};

use crate::{
    entry_table::{EntryTable, EntryTableValue},
    structs::BlockType,
    CallbackError, EncryptedTable, Error, FindexCallbacks, FindexCompact, IndexedValue,
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
    // to get `batch_fetch_chains()`
    + FindexCompact<
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
    /// Ratio of the noise over the real data.
    const NOISE_RATIO: f64;

    /// Number of noisy Entry Table UIDs to compact in a row.
    const BATCH_SIZE: usize;

    /// Selects a set of Entry Table UIDs to reindex and a set of Entry Table
    /// UIDs used as noise.
    ///
    /// # Parameters
    ///
    /// - `rng`         : secure random number generator
    /// - `uids`        : set UIDs from which to select UIDs to reindex and noise
    /// - `n_compact`   : number of UIDs to compact
    async fn select_noisy_uids(
        &self,
        rng: &mut impl CryptoRngCore,
        num_reindexing_before_full_set: u32
    ) -> Result<(Vec<Uid<UID_LENGTH>>, HashSet<Uid<UID_LENGTH>>), Error<CustomError>> {
        let uids = self.fetch_all_entry_table_uids().await?;

        let entry_table_length = uids.len() as f64;
        let n_compact = ((entry_table_length * (entry_table_length.log2() + 0.58))
            / f64::from(num_reindexing_before_full_set))
        .ceil() as usize;

        // The number of compacted UIDs should leave enough unused UIDs for the noise.
        if (n_compact as f64  * (1f64 + Self::NOISE_RATIO)) > uids.len() as f64 {
            return Err(Error::CryptoError(format!(
                "Number of Entry Table UIDs to compact ({n_compact}) should not be greater than {}",
                uids.len() as f64 / (1f64 + Self::NOISE_RATIO)
            )));
        }

        // There are:
        // - `n_compact` UIDs to compact;
        // - `NOISE_RATIO * n_compact` UIDs for the noise, which is lower than `n_compact`.
        //
        // The total is lower than `2 * n_compact`. An upper bound is used to avoid reallocations.
        let mut noisy_uids_to_compact = Vec::with_capacity(2 * n_compact );
        let mut noise = HashSet::with_capacity(n_compact);

        // Needed because `uids` is moved in the loop condition.
        let n_uids = uids.len();
        for uid in uids {
            let tmp = rng.next_u32() as usize;
            if tmp % n_uids < n_compact {
                // Randomly select ~ `n_compact` UIDs.
                noisy_uids_to_compact.push(uid);
            } else if tmp % (n_uids - n_compact) < (Self::NOISE_RATIO * n_compact as f64) as usize {
                // Randomly select ~ `NOISE_RATIO * n_compact` UIDs.
                noise.insert(uid);
            }
        }

        Ok((noisy_uids_to_compact, noise))
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
        // TODO (TBZ): check if this cannot return a
        // `HashMap<Uid<UID_LENGTH>, HashSet<Uid<UID_LENGTH>>>`
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
            .batch_fetch_chains(&kwi_chain_table_uids)
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
            // TODO (TBZ): use the same trick everywhere to avoid allocating (do not consume the
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
        noisy_chain_values: &HashMap<Uid<UID_LENGTH>, HashSet<IndexedValue>>,
    ) -> Result<
        (
            EntryTable<UID_LENGTH, KWI_LENGTH>,
            HashMap<Uid<UID_LENGTH>, EncryptedTable<UID_LENGTH>>,
        ),
        Error<CustomError>,
    > {
        let mut noisy_entry_table = EntryTable::with_capacity(noisy_chain_values.len());
        let mut compacted_chains = HashMap::with_capacity(noisy_chain_values.len() - noise.len());
        let mut cache = HashMap::with_capacity(noisy_chain_values.len() - noise.len());

        println!("noisy chains: {noisy_chain_values:?}");
        println!("noise: {noise:?}");
        println!("remaining locations: {noisy_remaining_locations:?}");

        for (uid, encrypted_value) in noisy_encrypted_entry_table.iter() {
            let entry_table_value = EntryTableValue::decrypt::<DEM_KEY_LENGTH, DemScheme>(
                k_value,
                encrypted_value
            )?;
            if noise.contains(uid) {
                // Noise entries are simply re-encrypted.
                noisy_entry_table.insert(uid.clone(), entry_table_value);
            } else {
                // Compact chains associated to the other entries.
                let chain = noisy_chain_values.get(uid).ok_or(Error::<CustomError>::CryptoError("No matching UID in chains.".to_string()))?;
                let mut compacted_chain = HashMap::with_capacity(chain.len());
                for value in chain {
                    match value {
                        IndexedValue::Location(location) => {
                            if noisy_remaining_locations.contains(location) {
                                // Add remaining locations back. All deletions should have been
                                // filtered by the fetch.
                                compacted_chain.insert(
                                    IndexedValue::from(location.clone()),
                                    BlockType::Addition,
                                );
                            }
                        }
                        IndexedValue::NextKeyword(keyword) => {
                            // TODO (TBZ): deal with obsolete `NextWord`s. For now just add the
                            // `NextWord` again.
                            compacted_chain
                                .insert(IndexedValue::from(keyword.clone()), BlockType::Addition);
                        }
                    };
                }
                compacted_chains.insert(entry_table_value.keyword_hash, compacted_chain);
                cache.insert(entry_table_value.keyword_hash, uid.clone());
            }
        }

        println!("Recompacted chains: {compacted_chains:?}");

        let compacted_chain_table = noisy_entry_table.upsert::<
            CHAIN_TABLE_WIDTH,
            BLOCK_LENGTH,
            KMAC_KEY_LENGTH,
            DEM_KEY_LENGTH,
            KmacKey,
            DemScheme
        >(rng, &compacted_chains, &cache)?;

        println!("Noisy compacted Entry Table: {noisy_entry_table:?}");

        Ok((noisy_entry_table, compacted_chain_table))
    }

    /// Live compact the given UIDs.
    async fn live_compact_uids(
        &mut self,
        rng: &mut impl CryptoRngCore,
        k_value: &DemScheme::Key,
        noisy_uids: Vec<Uid<UID_LENGTH>>,
        noise: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<(), Error<CustomError>> {
        // Fetch all index entries (noisy).
        let mut noisy_encrypted_entry_table = self
            .fetch_entry_table(&HashSet::from_iter(noisy_uids.into_iter()))
            .await?;

        // Fetch chain data (noisy).
        let (noisy_chain_uids, noisy_chain_values) = self
            .fetch_chain_data(
                k_value,
                &noisy_encrypted_entry_table,
            )
            .await?;

        // Select remaining locations (noisy).
        let noisy_locations: HashSet<Location> = noisy_chain_values
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
                noise,
                &noisy_remaining_locations,
                &noisy_encrypted_entry_table,
                &noisy_chain_values,
            )?;

            // Insert all recompacted chains first.
            self.insert_chain_table(&new_chains.iter().flat_map(|(_, v)| v.clone()).collect()).await?;

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
            chains_to_delete.extend(
                // - new chains corresponding to unsuccessful upserts
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

            chains_to_delete.extend(
                // - old chains corresponding to successful upserts
                noisy_chain_uids
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
        key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        num_reindexing_before_full_set: u32,
    ) -> Result<(), Error<CustomError>> {
        let mut rng = CsRng::from_entropy();

        let k_value =
            key.derive_dem_key::<DEM_KEY_LENGTH, DemScheme::Key>(ENTRY_TABLE_KEY_DERIVATION_INFO);

        let (noisy_entry_table_uids, noise) = self.select_noisy_uids(&mut rng, num_reindexing_before_full_set).await?;

        // Compact the selected Entry Table UIDs by batch (noisy).
        for noisy_uids_to_compact in noisy_entry_table_uids.chunks(Self::BATCH_SIZE) {
            self.live_compact_uids(
                &mut rng,
                &k_value,
                noisy_uids_to_compact.to_vec(),
                &noise,
            ).await?;
        }

        Ok(())
    }
}
