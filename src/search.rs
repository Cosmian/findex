//! This modules defines the `FindexSearch` trait.

use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::symmetric_crypto::{Dem, SymKey};

use crate::{
    callbacks::{FetchChains, FindexCallbacks},
    chain_table::KwiChainUids,
    entry_table::{EntryTable, EntryTableValue},
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
    /// Searches for a set of `Keyword`s, returning the corresponding
    /// `IndexedValue`s.
    ///
    /// # Parameters
    ///
    /// - `k_uid`               : KMAC key used to generate Entry Table UIDs
    /// - `k_value`             : DEM key used to decrypt the Entry Table
    /// - `label`               : public label
    /// - `keywords`            : keywords to search
    async fn core_search(
        &mut self,
        k_uid: &KmacKey,
        k_value: &DemScheme::Key,
        label: &Label,
        keywords: &HashSet<Keyword>,
    ) -> Result<HashMap<Keyword, HashSet<IndexedValue>>, Error<CustomError>> {
        // Derive Entry Table UIDs from keywords.
        let entry_table_uid_map = keywords
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
        let entry_table = self
            .fetch_entry_table(entry_table_uid_map.keys().copied().collect())
            .await?;

        // Unchain all Entry Table values.
        let mut kwi_chain_table_uids = KwiChainUids::with_capacity(entry_table.len());
        let mut kwi_to_keyword = HashMap::with_capacity(entry_table.len());
        for (uid, encrypted_value) in entry_table.into_iter() {
            let keyword = entry_table_uid_map.get(&uid).ok_or_else(|| {
                Error::<CustomError>::CryptoError(format!(
                    "Could not find keyword associated to UID {uid:?}."
                ))
            })?;
            let value = EntryTableValue::<UID_LENGTH, KWI_LENGTH>::decrypt::<
                DEM_KEY_LENGTH,
                DemScheme,
            >(k_value, &encrypted_value)
            .map_err(|_| {
                Error::<CustomError>::CryptoError(format!(
                    "fail to decrypt one of the `value` returned by the fetch entries callback \
                     (uid was '{uid:?}', value was {})",
                    if encrypted_value.is_empty() {
                        "empty".to_owned()
                    } else {
                        format!("'{encrypted_value:?}'")
                    },
                ))
            })?;
            kwi_to_keyword.insert(value.kwi.clone(), *keyword);
            let k_uid = value.kwi.derive_kmac_key(CHAIN_TABLE_KEY_DERIVATION_INFO);
            let chain = value.unchain::<
                            CHAIN_TABLE_WIDTH,
                            BLOCK_LENGTH,
                            KMAC_KEY_LENGTH,
                            DEM_KEY_LENGTH,
                            KmacKey,
                            DemScheme
                        >(&k_uid)?;
            kwi_chain_table_uids.insert(value.kwi, chain);
        }

        // Fetch the chain values.
        let chains = self.fetch_chains(kwi_chain_table_uids).await?;

        // Convert the blocks of the given chains into indexed values.
        let mut res = HashMap::<Keyword, HashSet<IndexedValue>>::with_capacity(chains.len());
        for (kwi, chain) in &chains {
            let keyword = kwi_to_keyword.get(kwi).ok_or_else(|| {
                Error::<CustomError>::CryptoError("Missing Kwi in reversed map.".to_string())
            })?;
            let blocks = chain
                .iter()
                .flat_map(|(_, chain_table_value)| chain_table_value.as_blocks());
            res.entry((*keyword).clone())
                .or_default()
                .extend(IndexedValue::from_blocks(blocks)?);
        }

        Ok(res)
    }

    /// Iteratively searches Findex indexes to build the graphs of the given
    /// keywords.
    ///
    /// For a given iteration:
    /// - search Findex for the targeted keywords
    /// - add these keywords with their indexed locations to the known graph
    /// - if a user interruption is received through the `progress` callback,
    ///   ignore the next keywords; otherwise mark them as targets for the next
    ///   iteration
    ///
    /// # Parameters
    ///
    /// - `master_key`          : Findex master secret key
    /// - `label`               : public label used for hashing
    /// - `keywords`            : keywords to search using Findex
    async fn iterative_search(
        &mut self,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
        mut keywords: HashSet<Keyword>,
    ) -> Result<HashMap<Keyword, HashSet<IndexedValue>>, Error<CustomError>> {
        let k_uid = master_key.derive_kmac_key(ENTRY_TABLE_KEY_DERIVATION_INFO);
        let k_value = master_key.derive_dem_key(ENTRY_TABLE_KEY_DERIVATION_INFO);

        let mut graph = HashMap::with_capacity(keywords.len());

        // Since keywords cannot be requested twice, the number of iterations can only
        // be smaller than the greatest depth of the searched keyword graphs.
        while !keywords.is_empty() {
            let results = self.core_search(&k_uid, &k_value, label, &keywords).await?;

            // Return early in case of user interrupt.
            let is_continue = self.progress(&results).await?;

            keywords = if is_continue {
                results
                    .values()
                    .flat_map(|indexed_values| {
                        indexed_values
                            .iter()
                            .filter_map(|value| value.get_keyword())
                            .filter(|next_keyword| !graph.contains_key(*next_keyword))
                            .cloned()
                    })
                    .collect()
            } else {
                HashSet::new()
            };

            graph.extend(results);
        }

        Ok(graph)
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
    async fn search(
        &mut self,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
        keywords: HashSet<Keyword>,
    ) -> Result<HashMap<Keyword, HashSet<Location>>, Error<CustomError>> {
        check_parameter_constraints::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH>();

        // Search Findex indexes to build the keyword graph.
        let graph = self
            .iterative_search(master_key, label, keywords.clone())
            .await?;

        // Walk the graph to get the results.
        keywords
            .into_iter()
            .map(|keyword| {
                let keyword_results = walk_graph_from(&keyword, &graph, &mut HashSet::new());
                Ok((keyword, keyword_results))
            })
            .collect()
    }
}

/// Retrieves the `Location`s stored in the given graph for the given
/// `Keyword`.
///
/// When a `NextWord` is found among the results, appends the results
/// of this `NextWord` from the graph to this keyword.
///
/// # Parameters
///
/// - `keyword`     : starting point of the walk
/// - `graph`       : keyword graph containing the Findex results
/// - `ancestors`   : keywords that have already been walked through
fn walk_graph_from<'a>(
    keyword: &'a Keyword,
    graph: &'a HashMap<Keyword, HashSet<IndexedValue>>,
    ancestors: &mut HashSet<&'a Keyword>,
) -> HashSet<Location> {
    // To prevent loop between `NextWord`s, we check if we already
    // got the locations for this keyword for the base keyword.
    if ancestors.contains(keyword) {
        return HashSet::new();
    } else {
        ancestors.insert(keyword);
    }

    // Early return if this keyword doesn't have any `IndexedValue`
    // to avoid allocation `with_capacity` below.
    let keyword_results = match graph.get(keyword) {
        Some(keyword_results) => keyword_results,
        None => return HashSet::new(),
    };

    let mut locations = HashSet::with_capacity(keyword_results.len());
    for indexed_value in keyword_results {
        match indexed_value {
            IndexedValue::Location(location) => {
                locations.insert(location.clone());
            }
            IndexedValue::NextKeyword(next_keyword) => {
                locations.extend(walk_graph_from(next_keyword, graph, ancestors));
            }
        }
    }

    locations
}
