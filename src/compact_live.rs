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

/// Live compact trait allows for compacting chains associated to a set of Entry
/// Table UIDs without interrupting the service.
///
/// The compaction of a chain removes duplicated entries, simplifies deletions
/// (removes all addition of the deleted keyword up to the deletion and removes
/// the deletion) and write remaining values in a compact way in the Chain Table
/// (only the last line of the chain may have padding blocks).
///
/// The following gives an example of the effect of a compact operation on an
/// Entry Table line and its associated chain.
///
/// The Entry Table line:
///
/// | UID | -> | H(w) | K_w | UID_5 |
///
/// becomes:
///
/// | UID | -> | H(w) | K_w' | UID_1' |
///
/// and the old chain (values are chosen arbitrarily in the aim to illustrate
/// different properties and `B1` ... `B4` are the non-padding blocks indexed
/// for the keyword `w`):
///
/// | UID_1 | -> Enc(K_w, | B1 (Add) | B2 (Add) |  Padding |)
/// | UID_2 | -> Enc(K_w, | B2 (Add) |  Padding |  Padding |)
/// | UID_3 | -> Enc(K_w, | B1 (Del) | B3 (Add) | B4 (Add) |)
/// | UID_4 | -> Enc(K_w, | B2 (Del) |  Padding |  Padding |)
/// | UID_5 | -> Enc(K_w, | B2 (Add) | B3 (Add) | B4 (Add) |)
///
/// becomes:
///
/// | UID_1' | -> Enc(K_w', | B2 (Add) | B3 (Add) | B4 (Add) |)
///
/// The following operations have been applied:
/// - a new random ephemeral key `K_w'` is drawn;
/// - the new last chain UID is stored in the Entry Table entry;
/// - chain UIDs are generated anew (random-like);
/// - chain values are encrypted under the new ephemeral key;
/// - `B1` is removed since its last occurrence in the chain is a deletion;
/// - `B2` is kept since its last occurrence is an addition and is simplified
///   (only one occurrence in the chain);
/// - `B3` and `B4` are kept since they have not been deleted, and simplified.
///
/// *NOTE*: the order of the locations in the compacted chain is not guaranteed.
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

    /// Selects a set of Entry Table UIDs to reindex (target set) and a set of Entry Table UIDs
    /// used as noise (noise set).
    ///
    /// These sets are mutually exclusive and the ratio of the cardinal of the noise set over the
    /// target set is given by `Self::NOISE_RATIO`.
    ///
    /// Returns the noisy taget set (target set + noise set) and the noise set.
    /// A HashSet is used for the noise set because lookup should be fast.
    ///
    /// # Parameters
    ///
    /// - `rng`                             : secure random number generator
    /// - `num_reindexing_before_full_set`  : number of compact operations need to compact all the
    /// base
    async fn select_noisy_uids(
        &self,
        rng: &mut impl CryptoRngCore,
        num_reindexing_before_full_set: u32
    ) -> Result<(Vec<Uid<UID_LENGTH>>, HashSet<Uid<UID_LENGTH>>), Error<CustomError>> {
        if Self::NOISE_RATIO > 1f64 {
            return Err(Error::CryptoError(format!(
                "noise ration cannot be greater than 1 ({} given)",
                Self::NOISE_RATIO
            )));
        }

        let uids = self.fetch_all_entry_table_uids().await?;

        // TODO (TBZ): find which probability is associated to this formula.
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

        // Upper bounds are used for capacity in order to avoid reallocations:
        // - the number of noise UIDs is lower than `n_compact`;
        let mut noise = HashSet::with_capacity(n_compact);
        // - the total number of UIDs (target set + noise set) is lower than `2*n_compact`.
        let mut noisy_uids_to_compact = Vec::with_capacity(2 * n_compact );

        // Needed because `uids` is moved in the loop condition.
        let n_uids = uids.len();
        let n_noise_candidates = n_uids - n_compact;
        let n_noise = (Self::NOISE_RATIO * n_compact as f64) as usize;

        for uid in uids {
            let tmp = rng.next_u32() as usize;
            if tmp % n_uids < n_compact {
                // Randomly select ~ `n_compact` UIDs.
                noisy_uids_to_compact.push(uid);
            } else if tmp % n_noise_candidates < n_noise {
                // Randomly select ~ `NOISE_RATIO * n_compact` UIDs.
                noise.insert(uid);
            }
        }

        Ok((noisy_uids_to_compact, noise))
    }

    /// Fetch all useful information for the compact from the Chain Table:
    /// - the map of Entry Table UIDs to Chain Table UIDs
    /// - the map of Entry Table UIDs to indexed values
    ///
    /// # Paramters
    ///
    /// - `k_value`                 : DEM key used to decrypt the Entry Table
    /// - `encrypted_entry_table`   : encrypted Entry Table
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
        let entry_table: EntryTable<UID_LENGTH, KWI_LENGTH> =
            EntryTable::decrypt::<DEM_KEY_LENGTH, DemScheme>(k_value, encrypted_entry_table)?;

        // Unchain all Entry Table UIDs.
        let kwi_chain_table_uids = entry_table.unchain::<
            CHAIN_TABLE_WIDTH,
            BLOCK_LENGTH,
            KMAC_KEY_LENGTH,
            DEM_KEY_LENGTH,
            KmacKey,
            DemScheme
        >(entry_table.keys(), usize::MAX);

        // Associate Entry Table UIDs to Chain Table UIDs.
        let chains = entry_table
            .iter()
            .map(|(uid, v)| {
                Ok((
                    uid.clone(),
                    kwi_chain_table_uids
                        .get(&v.kwi)
                        .ok_or(Error::<CustomError>::CryptoError(format!(
                            "no matching Kwi in `kwi_chain_table_uids` ({:?})",
                            v.kwi
                        )))?
                        .clone(),
                ))
            })
            .collect::<Result<HashMap<_, _>, Error<_>>>()?;

        // Fetch the Chain Table for the chain UIDs.
        let chain_values = self
            .batch_fetch_chains(&kwi_chain_table_uids)
            .await?;

        // Convert the blocks of the given chains into indexed values.
        let mut noisy_indexed_values = HashMap::new();
        for (entry_table_uid, entry_table_value) in entry_table.iter() {
            let chain =
                chain_values
                    .get(&entry_table_value.kwi)
                    .ok_or(Error::<CustomError>::CryptoError(format!(
                        "no matching Kwi in `kwi_chain_table_uids` ({:?})",
                        entry_table_value.kwi
                    )))?;
            let blocks = chain
                .iter()
                .flat_map(|(_, chain_table_value)| chain_table_value.as_blocks());
            noisy_indexed_values
                .insert(entry_table_uid.clone(), IndexedValue::from_blocks(blocks)?);
        }

        Ok((chains, noisy_indexed_values))
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
    /// - `k_value`                     : DEM key used to decrypt the Entry Table
    /// - `noise`                       : Entry Table UIDs used as noise
    /// - `noisy_remaining_locations`   : remaining locations (contains noise)
    /// - `noisy_encrypted_entry_table` : encrypted Entry Table (contains noise)
    /// - `noisy_chain_values`          : chain values (contains noise)
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
                compacted_chains.insert(uid.clone(), (entry_table_value.keyword_hash, compacted_chain));
                cache.insert(entry_table_value.keyword_hash, uid.clone());
            }
        }

        let compacted_chain_table = noisy_entry_table.upsert::<
            CHAIN_TABLE_WIDTH,
            BLOCK_LENGTH,
            KMAC_KEY_LENGTH,
            DEM_KEY_LENGTH,
            KmacKey,
            DemScheme
        >(rng, &compacted_chains)?;

        Ok((noisy_entry_table, compacted_chain_table))
    }

    /// Live compact the given UIDs.
    ///
    /// - `rng`         : secure random number generator
    /// - `k_value`     : DEM key used to decrypt the Entry Table
    /// - `noisy_uids`  : UIDs to compact (contains noise)
    /// - `noise`       : Entry Table UIDs used as noise
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

            self.delete_chain(&chains_to_delete).await?;
        }

        Ok(())
    }

    /// Compacts a random subset of the Entry Table.
    ///
    /// The size of this subset is such that `num_reindexing_before_full_set` compact operations
    /// are needed to compact all the Entry Table.
    ///
    /// - `master_key`                      : Findex master key
    /// - `num_reindexing_before_full_set`  : number of compact operations needed to compact all
    /// the Entry Table
    async fn live_compact(
        &mut self,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        num_reindexing_before_full_set: u32,
    ) -> Result<(), Error<CustomError>> {
        let mut rng = CsRng::from_entropy();

        let k_value =
            master_key.derive_dem_key::<DEM_KEY_LENGTH, DemScheme::Key>(ENTRY_TABLE_KEY_DERIVATION_INFO);

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
