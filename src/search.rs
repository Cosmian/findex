//! This modules defines the `FindexSearch` trait.

use std::collections::{HashMap, HashSet};

use async_recursion::async_recursion;
use cosmian_crypto_core::symmetric_crypto::{Dem, SymKey};

use crate::{
    callbacks::{FetchChains, FindexCallbacks},
    entry_table::EntryTable,
    error::CallbackError,
    parameters::check_parameter_constraints,
    structs::{IndexedValue, Keyword, Label, Location},
    Error, KeyingMaterial, ENTRY_TABLE_KEY_DERIVATION_INFO,
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
        let entry_table = EntryTable::decrypt::<DEM_KEY_LENGTH, DemScheme>(
            &k_value,
            &self
                .fetch_entry_table(entry_table_uid_map.keys().cloned().collect())
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
            .unchain::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH, KMAC_KEY_LENGTH, DEM_KEY_LENGTH, KmacKey, DemScheme>(
                entry_table_uid_map.keys(),
                max_results_per_keyword,
            );

        //
        // Query the Chain Table for these UIDs to recover the associated
        // chain values.
        //
        let chains = self.fetch_chains(kwi_chain_table_uids).await?;

        // Convert the blocks of the given chains into indexed values.
        let mut res = HashMap::new();
        for (kwi, chain) in &chains {
            let keyword = *reversed_map.get(kwi).ok_or_else(|| {
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
    async fn search(
        &mut self,
        keywords: &HashSet<Keyword>,
        master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
        label: &Label,
        max_results_per_keyword: usize,
        max_depth: usize,
        current_depth: usize,
    ) -> Result<HashMap<Keyword, HashSet<Location>>, Error<CustomError>> {
        check_parameter_constraints::<CHAIN_TABLE_WIDTH, BLOCK_LENGTH>();
        // Get indexed values associated to the given keywords
        let res = self
            .non_recursive_search(keywords, master_key, label, max_results_per_keyword)
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
}
