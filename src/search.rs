//! This modules defines the `FindexSearch` trait.

use std::collections::{HashMap, HashSet};

use async_recursion::async_recursion;
use cosmian_crypto_core::symmetric_crypto::{Dem, SymKey};

use crate::{
    callbacks::{FetchChains, FindexCallbacks},
    chain_table::KwiChainUids,
    entry_table::EntryTable,
    error::CallbackError,
    parameters::check_parameter_constraints,
    structs::{IndexedValue, Keyword, Label, Location},
    Error, KeyingMaterial, CHAIN_TABLE_KEY_DERIVATION_INFO, ENTRY_TABLE_KEY_DERIVATION_INFO,
};

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
>:
    Sized
    + FindexCallbacks<CustomError, UID_LENGTH>
    + FetchChains<
        UID_LENGTH,
        BLOCK_LENGTH,
        CHAIN_TABLE_WIDTH,
        KWI_LENGTH,
        DEM_KEY_LENGTH,
        DemScheme,
        CustomError,
    >
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
        let chains = self.fetch_chains(kwi_chain_table_uids).await?;

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

    /// Recursively searches Findex indexes to build the graph of the given
    /// keywords.
    ///
    /// For given recursion level:
    /// - search Findex for the given keywords
    /// - add these keywords with their indexed locations to the known graph
    /// - if the maximum recursion level is reached or a user interruption is
    ///   received through the `progress` callback, ignore the next keywords;
    ///   otherwise add them to the results of the associated keyword in the
    ///   graph and mark the unknown keywords for the next recursion
    /// - if there are some new keywords to search, call this function with
    ///   these new keywords as input
    ///
    /// # Parameters
    ///
    /// - `k_uid`               : KMAC key used to generate Entry Table UIDs
    /// - `k_value`             : DEM key used to decrypt the Entry Table
    /// - `label`               : public label used for hashing
    /// - `keywords`            : keywords to search using Findex
    /// - `graph`               : known keyword graph
    /// - `max_depth`           : maximum recursion level allowed
    /// - `current_depth`       : current depth reached by the recursion
    /// - `max_uid_per_chain`   : maximum number of UIDs to compute per keyword
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

    /// Searches for the `Location`s indexed by the given `Keyword`s. This is
    /// the entry point of the Findex search.
    ///
    /// # Parameters
    ///
    /// - `master_key`          : Findex master key
    /// - `label`               : public label
    /// - `keywords`            : keywords to search
    /// - `max_depth`           : maximum recursion depth allowed
    /// - `max_uid_per_chain`   : maximum number of UIDs to compute per chain
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

        // Search Findex indexes to build the keyword graph.
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
            results.insert(
                keyword.clone(),
                self.walk_graph_from(keyword, &graph, &mut HashSet::new())?,
            );
        }

        Ok(results)
    }

    /// Retrives the `Location`s stored in the given graph for the given
    /// `Keyword`.
    ///
    /// When a `NextWord` is found among the results and it has not been walked
    /// through yet, appends the results of the recursion on this `NextWord`.
    ///
    /// # Parameters
    ///
    /// - `keyword`     : starting point of the walk
    /// - `graph`       : keyword graph containing the Findex results
    /// - `ancestors`   : keywords that have already been walked through
    fn walk_graph_from<'a>(
        &self,
        keyword: &'a Keyword,
        graph: &'a HashMap<Keyword, HashSet<IndexedValue>>,
        ancestors: &mut HashSet<&'a Keyword>,
    ) -> Result<HashSet<Location>, Error<CustomError>> {
        ancestors.insert(keyword);
        if let Some(keyword_results) = graph.get(keyword) {
            let mut locations = HashSet::with_capacity(keyword_results.len());
            for indexed_value in keyword_results {
                match indexed_value {
                    IndexedValue::Location(location) => {
                        locations.insert(location.clone());
                    }
                    IndexedValue::NextKeyword(next_keyword) => {
                        if !ancestors.contains(next_keyword) {
                            locations.extend(self.walk_graph_from(
                                next_keyword,
                                graph,
                                ancestors,
                            )?);
                        }
                    }
                }
            }
            Ok(locations)
        } else {
            Ok(HashSet::new())
        }
    }
}
