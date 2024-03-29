use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;
use tracing::debug;

use super::{structs::Entry, Operation};
use crate::{
    edx::{Token, TokenDump},
    findex_mm::{structs::Link, CompactingData, FindexMultiMap, MmEnc},
    parameters::{BLOCK_LENGTH, LINE_WIDTH, SEED_LENGTH},
    DbInterfaceErrorTrait, DxEnc, Error, Label, ENTRY_LENGTH, LINK_LENGTH,
};

impl<
        UserError: DbInterfaceErrorTrait,
        EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>> + TokenDump<Error = Error<UserError>>,
        ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
    > FindexMultiMap<UserError, EntryTable, ChainTable>
{
    /// Returns the set of Entry Table tokens.
    pub async fn dump_entry_tokens(&self) -> Result<Vec<Token>, Error<UserError>> {
        Ok(self.entry_table.dump_tokens().await?.into_iter().collect())
    }

    /// Fetches all chains associated to the given tokens.
    ///
    /// # Returns
    ///
    /// All the data needed to compact targeted chains only.
    pub async fn prepare_compacting(
        &self,
        key: &<Self as MmEnc<SEED_LENGTH, UserError>>::Key,
        tokens: HashSet<Token>,
        compact_target: &HashSet<Token>,
    ) -> Result<(HashMap<Token, HashSet<Vec<u8>>>, CompactingData<ChainTable>), Error<UserError>>
    {
        let entries = self.fetch_entries(key, tokens).await?;

        let n_entries = entries.len();
        let entries = entries.into_iter().try_fold(
            HashMap::with_capacity(n_entries),
            |mut acc, (k, v)| {
                let old_v = acc.insert(k, v);
                if old_v.is_some() {
                    Err(Error::<UserError>::Crypto(
                        "Entry Table keys are not unique".to_string(),
                    ))
                } else {
                    Ok(acc)
                }
            },
        )?;

        let chain_metadata = entries
            .iter()
            .filter(|(token, _)| compact_target.contains(token))
            .map(|(token, entry)| (*token, self.derive_metadata(entry)))
            .collect::<HashMap<_, _>>();

        let encrypted_links = self
            .chain_table
            .get(
                chain_metadata
                    .iter()
                    .flat_map(|(_, (_, chain_tokens))| chain_tokens)
                    .copied()
                    .collect(),
            )
            .await?;

        let n_links = encrypted_links.len();
        let encrypted_links = encrypted_links.into_iter().try_fold(
            HashMap::with_capacity(n_links),
            |mut acc, (k, v)| {
                let old_v = acc.insert(k, v);
                if old_v.is_some() {
                    Err(Error::<UserError>::Crypto(
                        "Entry Table keys are not unique".to_string(),
                    ))
                } else {
                    Ok(acc)
                }
            },
        )?;

        let indexed_chains = chain_metadata
            .iter()
            .map(|(entry_token, (chain_key, chain_tokens))| {
                let links = chain_tokens
                    .iter()
                    .filter_map(|token| encrypted_links.get(token))
                    .map(|encrypted_link| {
                        self.chain_table
                            .resolve(chain_key, encrypted_link)
                            .map(Link)
                    })
                    // Collect in a vector to preserve the chain order.
                    .collect::<Result<Vec<_>, _>>()?;

                Ok((
                    *entry_token,
                    self.recompose::<BLOCK_LENGTH, LINE_WIDTH>(&links)?,
                ))
            })
            .collect::<Result<_, Error<UserError>>>()?;

        Ok((
            indexed_chains,
            CompactingData {
                metadata: chain_metadata,
                entries,
            },
        ))
    }

    /// Completes the compacting operation:
    /// 1. computes new links from the given `indexed_values` and updates
    ///    associated entries.
    /// 2. uses the `new_key` to generate a new token and encrypt each entry
    /// 3. tries applying modifications, reverts modifications upon failure or
    ///    remove old data upon success
    #[tracing::instrument(skip_all)]
    pub async fn complete_compacting(
        &self,
        rng: Arc<Mutex<impl CryptoRngCore>>,
        new_key: &<Self as MmEnc<SEED_LENGTH, UserError>>::Key,
        remaining_associations: HashMap<Token, HashSet<Vec<u8>>>,
        mut continuation: CompactingData<ChainTable>,
        new_label: &Label,
    ) -> Result<(), Error<UserError>> {
        let remaining_entry_tokens = continuation
            .entries
            .keys()
            .filter(|token| {
                remaining_associations
                    .get(token)
                    .map_or(true, |associated_values| !associated_values.is_empty())
            })
            .copied()
            .collect::<HashSet<_>>();

        debug!(
            "Step 1: computes new chains from the given `indexed_map` and updates associated \
             entries."
        );

        // Allocates a lower bound on the number of links.
        let mut new_links = HashMap::with_capacity(remaining_associations.len());
        for (entry_token, chain_values) in remaining_associations {
            let chain_links = self.decompose::<BLOCK_LENGTH, LINE_WIDTH>(
                &chain_values
                    .into_iter()
                    .map(|v| (Operation::Addition, v))
                    .collect::<Vec<_>>(),
            )?;

            let old_entry = continuation.entries.get_mut(&entry_token).ok_or_else(|| {
                Error::<UserError>::Crypto(format!(
                    "{entry_token:?} not found in entries from the continuation data"
                ))
            })?;

            let rng = &mut *rng.lock().expect("could not lock mutex");
            let mut new_entry =
                Entry::new(self.chain_table.gen_seed(rng), old_entry.tag_hash, None);

            let chain_key = self.chain_table.derive_keys(&new_entry.seed);
            let chain_tokens =
                self.derive_chain_tokens(&chain_key, new_entry.tag_hash.into(), chain_links.len());
            new_entry.chain_token = chain_tokens.last().copied();
            for (token, link) in chain_tokens.into_iter().zip(chain_links) {
                new_links.insert(
                    token,
                    self.chain_table.prepare(&mut *rng, &chain_key, link.0)?,
                );
            }
            *old_entry = new_entry;
        }

        let old_links = continuation
            .metadata
            .values()
            .flat_map(|(_, chain_tokens)| chain_tokens)
            .copied()
            .collect();

        debug!("Step 2: uses the `new_key` to generate a new token and encrypt each entry");

        let mut old_entries = HashSet::with_capacity(continuation.entries.len());
        let mut new_entries = HashMap::with_capacity(continuation.entries.len());
        {
            let rng = &mut *rng.lock().expect("could not lock mutex");
            for (token, entry) in continuation.entries {
                old_entries.insert(token);
                if remaining_entry_tokens.get(&token).is_some() {
                    new_entries.insert(
                        self.entry_table
                            .tokenize(new_key, &entry.tag_hash, Some(new_label)),
                        self.entry_table.prepare(rng, new_key, entry.into())?,
                    );
                }
            }
        }
        let new_links_tokens = new_links.keys().copied().collect();
        let new_entry_tokens = new_entries.keys().copied().collect();

        debug!(
            "Step 3: tries applying modifications, reverts modifications upon failure or removes \
             old data upon success"
        );

        let res = self.chain_table.insert(new_links).await;
        if res.is_err() {
            self.chain_table.delete(new_links_tokens).await?;
            return Err(Error::Crypto(format!(
                "An error occurred during the insert operation. All modifications were reverted. \
                 ({res:?})"
            )));
        };

        let res = self.entry_table.insert(new_entries).await.map_err(|e| {
            Error::Crypto(format!(
                "An error occurred during the `insert` operation, all modifications were reverted: {e}"
            ))
        });

        if res.is_ok() {
            self.chain_table.delete(old_links).await?;
            self.entry_table.delete(old_entries).await?;
        } else {
            self.chain_table.delete(new_links_tokens).await?;
            self.entry_table.delete(new_entry_tokens).await?;
        }

        res
    }
}
