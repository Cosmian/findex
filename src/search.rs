//! This modules defines the `FindexSearch` trait.

use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
};

use async_recursion::async_recursion;
use cosmian_crypto_core::{
    bytes_ser_de::Serializable,
    symmetric_crypto::{Dem, SymKey},
};
use futures::future::join_all;

use crate::{
    callbacks::FindexCallbacks,
    chain_table::{ChainTableValue, KwiChainUids},
    entry_table::EntryTable,
    error::CallbackError,
    structs::{Block, IndexedValue, Keyword, Label, Location, Uid},
    Error, KeyingMaterial, CHAIN_TABLE_KEY_DERIVATION_INFO, ENTRY_TABLE_KEY_DERIVATION_INFO,
};

/// Trait implementing the search functionality of Findex.
pub trait FindexSearch<
    const UID_LENGTH: usize,
    const BLOCK_LENGTH: usize,
    const TABLE_WIDTH: usize,
    const MASTER_KEY_LENGTH: usize,
    const KWI_LENGTH: usize,
    const KMAC_KEY_LENGTH: usize,
    const DEM_KEY_LENGTH: usize,
    KmacKey: SymKey<KMAC_KEY_LENGTH>,
    DemScheme: Dem<DEM_KEY_LENGTH>,
    CustomError: std::error::Error + CallbackError,
>: Sized + FindexCallbacks<CustomError, UID_LENGTH>
{
    /// Searches for a set of keywords, returning the corresponding indexed
    /// values.
    ///
    /// *Note*: An `IndexedValue` can be either a `Location` or another
    /// `Keyword`.
    ///
    /// # Parameters
    ///
    /// - `keywords`                : keywords to search
    /// - `master_key`              : user secret key
    /// - `label`                   : public label
    /// - `max_results_per_keyword` : maximum number of results to return per
    ///   keyword
    async fn non_recursive_search(
        &mut self,
        keywords: &HashSet<Keyword>,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
        max_results_per_keyword: usize,
        fetch_chains_batch_size: NonZeroUsize,
    ) -> Result<HashMap<Keyword, HashSet<IndexedValue>>, Error<CustomError>> {
        if keywords.is_empty() {
            return Ok(HashMap::new());
        }

        // Derive DEM and KMAC keys
        let k_uid: KmacKey = master_key.derive_kmac_key(ENTRY_TABLE_KEY_DERIVATION_INFO);
        let k_value = master_key.derive_dem_key(ENTRY_TABLE_KEY_DERIVATION_INFO);

        //
        // Derive Entry Table UIDs from keywords
        //
        let entry_table_uid_map = keywords
            .iter()
            .map(|keyword| {
                (
                    EntryTable::<UID_LENGTH, KWI_LENGTH>::generate_uid(
                        &k_uid,
                        &keyword.hash(),
                        label,
                    ),
                    keyword,
                )
            })
            .collect::<HashMap<_, _>>();

        //
        // Query the Entry Table for these UIDs
        //
        let entry_table = EntryTable::decrypt::<BLOCK_LENGTH, DEM_KEY_LENGTH, DemScheme>(
            &k_value,
            &self
                .fetch_entry_table(&entry_table_uid_map.keys().cloned().collect())
                .await?,
        )?;

        // Build the reversed map `Kwi <-> keyword`.
        let reversed_map = entry_table
            .iter()
            .map(|(uid, value)| -> Result<_, _> {
                let keyword = entry_table_uid_map.get(uid).ok_or_else(|| {
                    Error::<CustomError>::CryptoError(format!(
                        "Could not find keyword associated to UID {uid:?}."
                    ))
                })?;
                Ok((&value.kwi, *keyword))
            })
            .collect::<Result<HashMap<_, _>, Error<_>>>()?;

        //
        // Get all the corresponding Chain Table UIDs
        //
        let kwi_chain_table_uids = entry_table
            .unchain::<BLOCK_LENGTH, KMAC_KEY_LENGTH, DEM_KEY_LENGTH, KmacKey, DemScheme>(
                entry_table_uid_map.keys(),
                max_results_per_keyword,
            );

        //
        // Query the Chain Table for these UIDs to recover the associated
        // chain values.
        //
        let chains = self
            .noisy_fetch_chains(&kwi_chain_table_uids, fetch_chains_batch_size)
            .await?;

        // Convert the block of the given chains into indexed values.
        let mut res = HashMap::<Keyword, HashSet<IndexedValue>>::new();
        for (kwi, chain) in chains {
            let keyword = *reversed_map.get(&kwi).ok_or_else(|| {
                Error::<CustomError>::CryptoError("Missing Kwi in reversed map.".to_string())
            })?;
            let entry = res.entry(keyword.clone()).or_default();
            let blocks = chain.into_iter().flat_map(|(_, v)| v).collect::<Vec<_>>();
            for bytes in Block::unpad(&blocks)? {
                entry.insert(IndexedValue::try_from_bytes(&bytes)?);
            }
        }
        Ok(res)
    }

    /// Recursively searches Findex indexes for locations indexed by the given
    /// keywords.
    ///
    /// *Note*: `current_depth` is usually 0 when called outside this function.
    ///
    /// # Parameters
    ///
    /// - `keywords`                : keywords to search using Findex
    /// - `master_key`              : user secret key
    /// - `label`                   : public label used for hashing
    /// - `max_results_per_keyword` : maximum number of results to fetch per
    ///   keyword
    /// - `max_depth`               : maximum recursion level allowed
    /// - `current_depth`           : current depth reached by the recursion
    #[async_recursion(?Send)]
    #[allow(clippy::too_many_arguments)]
    async fn search(
        &mut self,
        keywords: &HashSet<Keyword>,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
        max_results_per_keyword: usize,
        max_depth: usize,
        fetch_chains_batch_size: NonZeroUsize,
        current_depth: usize,
    ) -> Result<HashMap<Keyword, HashSet<Location>>, Error<CustomError>> {
        // Get indexed values associated to the given keywords
        let res = self
            .non_recursive_search(
                keywords,
                master_key,
                label,
                max_results_per_keyword,
                fetch_chains_batch_size,
            )
            .await?;

        // Send current results (Location and NextKeyword) to the callback.
        let continue_recursion = self.progress(&res).await?;

        // Sort indexed values into keywords and locations.
        let mut keyword_map = HashMap::new();
        let mut results = HashMap::new();
        for (keyword, indexed_values) in res {
            let results_entry: &mut HashSet<Location> = results.entry(keyword.clone()).or_default();
            for value in indexed_values {
                match value {
                    IndexedValue::Location(_) => {
                        results_entry.insert(value.try_into().unwrap());
                    }
                    IndexedValue::NextKeyword(next_keyword) => {
                        keyword_map.insert(next_keyword, keyword.clone());
                    }
                };
            }
        }

        // Stop recursion if `progress_callback` returned false or all branches have
        // been explored or max depth is reached
        if continue_recursion && !(keyword_map.is_empty() || current_depth == max_depth) {
            // Add results from the next recursion.
            for (keyword, indexed_values) in self
                .search(
                    &keyword_map.keys().cloned().collect(),
                    master_key,
                    label,
                    max_results_per_keyword,
                    max_depth,
                    fetch_chains_batch_size,
                    current_depth + 1,
                )
                .await?
            {
                let prev_keyword = keyword_map.get(&keyword).ok_or_else(|| {
                    Error::<CustomError>::CryptoError(
                        "Could not find previous keyword in cache.".to_string(),
                    )
                })?;
                let entry = results.entry(prev_keyword.clone()).or_default();
                entry.extend(indexed_values);
            }
        }

        Ok(results)
    }

    /// Fetches the values of the given chains from the Chain Table with noise.
    ///
    /// Security is based on the noisiness of the process under the assumption
    /// that several requests are performed in parallel. Requests to the Chain
    /// Table are done UID per UID. This makes it more difficult for the server
    /// to link a given Chain Table UID request with a previously received
    /// Entry Table UID request.
    ///
    /// - `kwi_chain_table_uids`    : Maps `Kwi`s to sets of Chain Table UIDs
    async fn noisy_fetch_chains(
        &self,
        kwi_chain_table_uids: &KwiChainUids<UID_LENGTH, KWI_LENGTH>,
        batch_size: NonZeroUsize,
    ) -> Result<
        HashMap<KeyingMaterial<KWI_LENGTH>, Vec<(Uid<UID_LENGTH>, ChainTableValue<BLOCK_LENGTH>)>>,
        Error<CustomError>,
    > {
        let mut chains = HashMap::with_capacity(kwi_chain_table_uids.len());
        for (kwi, chain_table_uids) in kwi_chain_table_uids.iter() {
            let kwi_value: DemScheme::Key = kwi.derive_dem_key(CHAIN_TABLE_KEY_DERIVATION_INFO);
            let mut chain = Vec::with_capacity(chain_table_uids.len());

            // Fetch all chain table values by batch of `batch_size` to increase noise.
            let chain_table_uids_hashset: Vec<_> = chain_table_uids
                .chunks(batch_size.into())
                .map(|uids| uids.iter().cloned().collect())
                .collect();

            let mut futures = Vec::with_capacity(chain_table_uids_hashset.len());
            for uid in &chain_table_uids_hashset {
                futures.push(self.fetch_chain_table(uid));
            }

            let encrypted_items = join_all(futures).await;

            for encrypted_item in encrypted_items {
                // Use a vector not to shuffle the chain. This is important because indexed
                // values can be divided in blocks that span several lines in the chain.
                for (uid, value) in encrypted_item? {
                    let decrypted_value = ChainTableValue::<BLOCK_LENGTH>::decrypt::<
                        TABLE_WIDTH,
                        DEM_KEY_LENGTH,
                        DemScheme,
                    >(&kwi_value, &value)
                    .map_err(|_| {
                        Error::<CustomError>::CryptoError(format!(
                            "fail to decrypt one of the `value` returned by the fetch chains \
                             callback (uid was '{uid:?}', value was {})",
                            if value.is_empty() {
                                "empty".to_owned()
                            } else {
                                format!("'{value:?}'")
                            },
                        ))
                    })?;

                    chain.push((uid, decrypted_value));
                }
            }
            chains.insert(kwi.clone(), chain);
        }

        Ok(chains)
    }
}
