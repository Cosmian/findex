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
use rand::{seq::SliceRandom, thread_rng};

use super::{callbacks::FindexCallbacks, structs::Block};
use crate::{
    core::{
        chain_table::{ChainTableValue, KwiChainUids},
        entry_table::EntryTable,
        structs::{IndexedValue, Keyword, Label, Uid},
        KeyingMaterial, CHAIN_TABLE_KEY_DERIVATION_INFO, ENTRY_TABLE_KEY_DERIVATION_INFO,
    },
    error::FindexErr,
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
>: Sized + FindexCallbacks<UID_LENGTH>
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
    ) -> Result<HashMap<Keyword, HashSet<IndexedValue>>, FindexErr> {
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
                    FindexErr::CryptoError(format!(
                        "Could not find keyword associated to UID {uid:?}."
                    ))
                })?;
                Ok((&value.kwi, *keyword))
            })
            .collect::<Result<HashMap<_, _>, FindexErr>>()?;

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
            let keyword = *reversed_map
                .get(&kwi)
                .ok_or_else(|| FindexErr::CryptoError(String::new()))?;
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
    ) -> Result<HashMap<Keyword, HashSet<IndexedValue>>, FindexErr> {
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
        // Stop here if there is no result
        if res.is_empty() {
            return Ok(res);
        }

        // Sort indexed values into keywords and locations.
        let mut keyword_map = HashMap::new();
        let mut results = HashMap::new();
        for (keyword, indexed_values) in res {
            let results_entry: &mut HashSet<IndexedValue> =
                results.entry(keyword.clone()).or_default();
            for value in indexed_values {
                match value {
                    IndexedValue::Location(_) => {
                        results_entry.insert(value);
                    }
                    IndexedValue::NextKeyword(next_keyword) => {
                        if current_depth == max_depth {
                            // `NextKeyword`s are returned if recursion couldn't reach the leaves.
                            results_entry.insert(IndexedValue::NextKeyword(next_keyword));
                        } else {
                            keyword_map.insert(next_keyword, keyword.clone());
                        }
                    }
                };
            }
        }

        if keyword_map.is_empty() {
            // All branches have been explored.
            return Ok(results);
        }

        // Send current results to the callback.
        let is_to_continue = self.progress(&results).await?;

        if is_to_continue {
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
                    FindexErr::CryptoError("Could not find previous keyword in cache.".to_string())
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
        FindexErr,
    > {
        let mut chain_table_uids: Vec<_> = kwi_chain_table_uids
            .iter()
            .flat_map(|(_, uids)| uids.clone())
            .collect();

        let mut rng = thread_rng();
        chain_table_uids.shuffle(&mut rng);

        // Fetch all chain table values by batch of `batch_size` to increase noise.
        let chain_table_uids_batched: Vec<_> = chain_table_uids
            .chunks(batch_size.into())
            .map(|uids| uids.iter().cloned().collect())
            .collect();

        let mut futures = Vec::with_capacity(chain_table_uids_batched.len());
        for uids in &chain_table_uids_batched {
            futures.push(self.fetch_chain_table(uids));
        }

        let mut chains_encrypted_values_by_uids = HashMap::with_capacity(chain_table_uids.len());
        for future_result in join_all(futures).await {
            for (uid, encrypted_value) in future_result? {
                chains_encrypted_values_by_uids.insert(uid, encrypted_value);
            }
        }

        let mut results = HashMap::with_capacity(kwi_chain_table_uids.len());
        for (kwi, chain_table_uids) in kwi_chain_table_uids.iter() {
            let kwi_value: DemScheme::Key = kwi.derive_dem_key(CHAIN_TABLE_KEY_DERIVATION_INFO);

            // Use a vector not to shuffle the chain. This is important because indexed
            // values can be divided in blocks that span several lines in the chain.
            let chains = results
                .entry(kwi.clone())
                .or_insert_with(|| Vec::with_capacity(chain_table_uids.len()));

            for uid in chain_table_uids {
                let value = chains_encrypted_values_by_uids.get(uid).ok_or_else(|| {
                    FindexErr::CryptoError(format!(
                        "fail to find the uid '{}' inside fetch chains callback response",
                        hex::encode(uid)
                    ))
                })?;

                let decrypted_value = ChainTableValue::<BLOCK_LENGTH>::decrypt::<
                    TABLE_WIDTH,
                    DEM_KEY_LENGTH,
                    DemScheme,
                >(&kwi_value, value)
                .map_err(|_| {
                    FindexErr::CallBack(format!(
                        "fail to decrypt one of the `value` returned by the fetch chains callback \
                         (uid as hex was '{}', value {})",
                        hex::encode(uid),
                        if value.is_empty() {
                            "was empty".to_owned()
                        } else {
                            format!("as hex was '{}'", hex::encode(value))
                        },
                    ))
                })?;

                chains.push((uid.clone(), decrypted_value));
            }
        }

        Ok(results)
    }
}
