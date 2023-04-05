//! This modules defines the `FindexSearch` trait.

use std::collections::{HashMap, HashSet};

use async_recursion::async_recursion;
use cosmian_crypto_core::symmetric_crypto::{Dem, SymKey};
use futures::future::join_all;

use crate::{
    callbacks::FindexCallbacks,
    chain_table::{ChainTableValue, KwiChainUids},
    entry_table::EntryTable,
    error::CallbackError,
    parameters::check_parameter_constraints,
    structs::{IndexedValue, Keyword, Label, Location, Uid},
    EncryptedTable, Error, KeyingMaterial, CHAIN_TABLE_KEY_DERIVATION_INFO,
    ENTRY_TABLE_KEY_DERIVATION_INFO,
};

/// Number of Entry Table UIDs to fetch in a row.
const BATCH_SIZE: usize = 100;

/// Trait implementing the search functionality of Findex.
pub trait FindexSearch<
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
    /// - `k_uid`               : KMAC key used to generate Entry Table UIDs
    /// - `k_value`             : DEM key used to decrypt the Entry Table
    /// - `label`               : public label
    /// - `keywords`            : keywords to search
    /// - `max_uid_per_chain`   : maximum number of UID per chain
    async fn core_search(
        &mut self,
        k_uid: &KmacKey,
        k_value: &DemScheme::Key,
        label: &Label,
        keywords: &HashSet<Keyword>,
        max_uid_per_chain: usize,
    ) -> Result<HashMap<Keyword, HashSet<IndexedValue>>, Error<CustomError>> {
        if keywords.is_empty() {
            return Ok(HashMap::new());
        }

        // Derive Entry Table UIDs from keywords.
        let mut entry_table_uid_map = keywords
            .iter()
            .map(|keyword| {
                (
                    EntryTable::<UID_LENGTH, KWI_LENGTH>::generate_uid(
                        k_uid,
                        &keyword.hash(),
                        label,
                    ),
                    keyword,
                )
            })
            .collect::<HashMap<_, _>>();

        // Query the Entry Table for these UIDs.
        let entry_table = EntryTable::decrypt::<DEM_KEY_LENGTH, DemScheme>(
            k_value,
            &self
                .fetch_entry_table(entry_table_uid_map.keys().copied().collect())
                .await?,
        )?;

        // Unchain all Entry Table values.
        let mut kwi_chain_table_uids = KwiChainUids::with_capacity(entry_table.len());
        let mut kwi_to_keyword = HashMap::with_capacity(entry_table.len());
        for (uid, value) in entry_table.into_iter() {
            let keyword = entry_table_uid_map.remove(&uid).ok_or_else(|| {
                Error::<CustomError>::CryptoError(format!(
                    "Could not find keyword associated to UID {uid:?}."
                ))
            })?;
            kwi_to_keyword.insert(value.kwi.clone(), keyword);
            let k_uid = value.kwi.derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);
            let chain = value.unchain::<
                            CHAIN_TABLE_WIDTH,
                            BLOCK_LENGTH,
                            KMAC_KEY_LENGTH,
                            DEM_KEY_LENGTH,
                            KmacKey,
                            DemScheme
                        >(&k_uid, max_uid_per_chain);
            kwi_chain_table_uids.insert(value.kwi, chain);
        }

        // Fetch the chain values.
        let chains = self
            .noisy_fetch_chains::<BATCH_SIZE>(kwi_chain_table_uids)
            .await?;

        // Convert the blocks of the given chains into indexed values.
        let mut res = HashMap::with_capacity(chains.len());
        for (kwi, chain) in &chains {
            let keyword = kwi_to_keyword.remove(kwi).ok_or_else(|| {
                Error::<CustomError>::CryptoError("Missing Kwi in reversed map.".to_string())
            })?;
            let blocks = chain
                .iter()
                .flat_map(|(_, chain_table_value)| chain_table_value.as_blocks());
            res.insert(keyword.clone(), IndexedValue::from_blocks(blocks)?);
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
    async fn recursive_search(
        &mut self,
        k_uid: &KmacKey,
        k_value: &DemScheme::Key,
        label: &Label,
        keywords: &HashSet<Keyword>,
        graph: &mut HashMap<Keyword, HashSet<IndexedValue>>,
        max_depth: usize,
        current_depth: usize,
        max_uid_per_chain: usize,
    ) -> Result<(), Error<CustomError>> {
        let current_results = self
            .core_search(k_uid, k_value, label, keywords, max_uid_per_chain)
            .await?;

        let continue_recursion = self.progress(&current_results).await?;

        let mut next_keywords = HashSet::with_capacity(current_results.len());
        for (keyword, indexed_values) in current_results {
            if continue_recursion && current_depth != max_depth {
                // Mark unknown keywords to be searched in the next recursion.
                next_keywords.extend(
                    indexed_values
                        .iter()
                        .filter_map(|value| value.get_keyword())
                        .filter(|next_keyword| !graph.contains_key(next_keyword))
                        .cloned(),
                );
                // Add all indexed values to the results.
                graph.insert(keyword, indexed_values);
            } else {
                // Do not add the next keyword to the results.
                graph.insert(
                    keyword,
                    indexed_values
                        .into_iter()
                        .filter(|value| value.is_location())
                        .collect(),
                );
            }
        }

        // Recurse if some keywords still need to be searched. An empty `next_keyword`
        // set means that there is no more keywords to search, that the user interrupted
        // the search or that the recursion has reached the maximum depth allowed.
        if !next_keywords.is_empty() {
            self.recursive_search(
                k_uid,
                k_value,
                label,
                &next_keywords,
                graph,
                max_depth,
                current_depth + 1,
                max_uid_per_chain,
            )
            .await?;
        }

        Ok(())
    }

    async fn search(
        &mut self,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
        keywords: &HashSet<Keyword>,
        max_depth: usize,
        max_uid_per_chain: usize,
    ) -> Result<HashMap<Keyword, HashSet<Location>>, Error<CustomError>> {
        check_parameter_constraints::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH>();

        let k_uid = master_key.derive_kmac_key(ENTRY_TABLE_KEY_DERIVATION_INFO);
        let k_value = master_key.derive_dem_key(ENTRY_TABLE_KEY_DERIVATION_INFO);

        // Search Findex to build the keyword graph.
        let mut graph = HashMap::with_capacity(keywords.len());
        self.recursive_search(
            &k_uid,
            &k_value,
            label,
            keywords,
            &mut graph,
            max_depth,
            0,
            max_uid_per_chain,
        )
        .await?;

        // Walk the graph to get the results.
        let mut results = HashMap::with_capacity(keywords.len());
        for keyword in keywords {
            results.insert(keyword.clone(), self.walk_graph_from(keyword, &graph)?);
        }

        Ok(results)
    }

    fn walk_graph_from(
        &self,
        keyword: &Keyword,
        graph: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<HashSet<Location>, Error<CustomError>> {
        if let Some(keyord_results) = graph.get(keyword) {
            let mut locations = HashSet::with_capacity(keyord_results.len());
            for indexed_value in keyord_results {
                match indexed_value {
                    IndexedValue::Location(location) => {
                        locations.insert(location.clone());
                    }
                    IndexedValue::NextKeyword(next_keyword) => {
                        locations.extend(self.walk_graph_from(next_keyword, graph)?);
                    }
                }
            }
            Ok(locations)
        } else {
            Ok(HashSet::new())
        }
    }

    /// Fetches the values of the given chains from the Chain Table by batch of
    /// size `batch_size`.
    ///
    /// Security is based on the noisiness of the process under the assumption
    /// that several requests are performed in parallel. Requests to the Chain
    /// Table are done UID per UID. This makes it more difficult for the server
    /// to link a given Chain Table UID request with a previously received
    /// Entry Table UID request.
    ///
    /// - `kwi_chain_table_uids`    : Maps `Kwi`s to sets of Chain Table UIDs
    async fn noisy_fetch_chains<const BATCH_SIZE: usize>(
        &self,
        kwi_chain_table_uids: KwiChainUids<UID_LENGTH, KWI_LENGTH>,
    ) -> Result<
        HashMap<
            KeyingMaterial<KWI_LENGTH>,
            Vec<(
                Uid<UID_LENGTH>,
                ChainTableValue<CHAIN_TABLE_WIDTH, BLOCK_LENGTH>,
            )>,
        >,
        Error<CustomError>,
    > {
        let mut res = HashMap::with_capacity(kwi_chain_table_uids.len());

        // Collect to a `HashSet` to mix UIDs between chains.
        let chain_table_uids = kwi_chain_table_uids
            .values()
            .flatten()
            .cloned()
            .collect::<HashSet<_>>();

        let mut futures = Vec::with_capacity(chain_table_uids.len() / BATCH_SIZE + 1);
        let mut is_empty = false;
        let mut chain_table_uids = chain_table_uids.into_iter();

        while !is_empty {
            match chain_table_uids.next_chunk::<BATCH_SIZE>() {
                Ok(batch) => futures.push(self.fetch_chain_table(batch.iter().cloned().collect())),
                Err(batch) => {
                    futures.push(self.fetch_chain_table(batch.collect()));
                    is_empty = true;
                }
            }
        }

        let mut encrypted_items: EncryptedTable<UID_LENGTH> =
            join_all(futures).await.into_iter().flatten().collect();

        for (kwi, chain_table_uids) in kwi_chain_table_uids.into_iter() {
            let kwi_value = kwi.derive_dem_key(CHAIN_TABLE_KEY_DERIVATION_INFO);

            // Use a vector not to shuffle the chain. This is important because indexed
            // values can be divided in blocks that span several lines in the chain.
            let mut chain = Vec::with_capacity(chain_table_uids.len());

            for uid in chain_table_uids {
                let (uid, encrypted_value) =
                    encrypted_items
                        .remove_entry(&uid)
                        .ok_or(Error::<CustomError>::CryptoError(format!(
                            "no Chain Table entry with UID '{uid:?}' in fetch result",
                        )))?;
                chain.push((
                    uid,
                    ChainTableValue::decrypt::<DEM_KEY_LENGTH, DemScheme>(
                        &kwi_value,
                        &encrypted_value,
                    )?,
                ));
            }

            res.insert(kwi, chain);
        }

        Ok(res)
    }
}
