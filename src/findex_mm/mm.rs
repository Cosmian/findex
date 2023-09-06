//! Implements MM-Enc for `FindexMultiMap`.

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;
use tiny_keccak::{Hasher, Sha3};

use crate::{
    edx::DxEnc,
    error::{CoreError, Error},
    findex_mm::{
        structs::{Entry, Link, Operation},
        FindexMultiMap, MmEnc, ENTRY_LENGTH, LINK_LENGTH,
    },
    parameters::{BLOCK_LENGTH, HASH_LENGTH, LINE_WIDTH, SEED_LENGTH},
    CallbackErrorTrait, Label,
};

impl<
        UserError: CallbackErrorTrait,
        EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>>,
        ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
    > FindexMultiMap<UserError, EntryTable, ChainTable>
{
    /// Instantiates a new `FindexMultiMap`.
    pub fn new(entry_table: EntryTable, chain_table: ChainTable) -> Self {
        Self {
            entry_table,
            chain_table,
        }
    }

    /// Derives all chain tokens from the given `seed` and `key`.
    pub(crate) fn unroll(
        &self,
        key: &ChainTable::Key,
        seed: &[u8; HASH_LENGTH],
        last_token: &ChainTable::Token,
    ) -> Vec<ChainTable::Token> {
        let mut chain = Vec::new();
        chain.push(self.chain_table.tokenize(key, seed, None));
        while &chain[chain.len() - 1] != last_token {
            chain.push(
                self.chain_table
                    .tokenize(key, &chain[chain.len() - 1], None),
            );
        }
        chain
    }

    /// Derives `n` new chain tokens following the `last_token`.
    pub(crate) fn derive_chain_tokens(
        &self,
        ct_key: &ChainTable::Key,
        mut last_token: ChainTable::Token,
        n: usize,
    ) -> Result<Vec<ChainTable::Token>, Error<UserError>> {
        let mut res = Vec::with_capacity(n);
        for _ in 0..n {
            let new_token = self.chain_table.tokenize(ct_key, &last_token, None);
            res.push(new_token);
            last_token = new_token;
        }
        Ok(res)
    }

    /// Fetches the entries associated to the given tags.
    async fn fetch_entries_by_tag<Tag: Hash + Eq + AsRef<[u8]>>(
        &self,
        key: &EntryTable::Key,
        tags: HashSet<Tag>,
        label: &Label,
    ) -> Result<Vec<(Tag, Entry<ChainTable>)>, Error<UserError>> {
        let mut tokens = tags
            .into_iter()
            .map(|tag| {
                let mut tag_hash = [0; HASH_LENGTH];
                let mut hasher = Sha3::v256();
                hasher.update(tag.as_ref());
                hasher.finalize(&mut tag_hash);
                (self.entry_table.tokenize(key, &tag_hash, Some(label)), tag)
            })
            .collect::<HashMap<_, _>>();

        let entries = self
            .fetch_entries(key, tokens.keys().copied().collect())
            .await?;

        Ok(entries
            .into_iter()
            .filter_map(|(token, entry)| tokens.remove(&token).map(|tag| (tag, entry)))
            .collect())
    }

    /// Fetches the Entry Table for the given tokens and decrypts the entries
    /// using the given key.
    pub(crate) async fn fetch_entries(
        &self,
        key: &EntryTable::Key,
        tokens: HashSet<EntryTable::Token>,
    ) -> Result<Vec<(EntryTable::Token, Entry<ChainTable>)>, Error<UserError>> {
        self.entry_table
            .get(tokens)
            .await?
            .into_iter()
            .map(|(token, encrypted_entry)| {
                self.entry_table
                    .resolve(key, &encrypted_entry)
                    .map(|entry| (token, Entry::from(entry)))
            })
            .collect()
    }

    /// Decomposes the given Findex index modifications into a sequence of Chain
    /// Table values.
    ///
    /// # Description
    ///
    /// Pads each value into blocks and push these blocks into a chain link,
    /// setting the flag bytes of each block according to the associated
    /// operation.
    pub(crate) fn decompose<const BLOCK_LENGTH: usize, const LINE_LENGTH: usize>(
        &self,
        modifications: &[(Operation, <Self as MmEnc<SEED_LENGTH, UserError>>::Item)],
    ) -> Result<Vec<Link>, Error<UserError>> {
        // Allocate a lower bound on the number of chain links.
        let mut chain = Vec::with_capacity(modifications.len());
        let mut link = Link::new();
        let mut pos = 0;

        for (operation, value) in modifications {
            let full_block_number = value.len() / BLOCK_LENGTH;

            for i in 0..full_block_number {
                link.set_operation(pos, *operation)?;
                link.set_block(pos, &value[i * BLOCK_LENGTH..(i + 1) * BLOCK_LENGTH], false)?;
                pos += 1;
                if pos == LINE_LENGTH {
                    chain.push(link);
                    link = Link::new();
                    pos = 0
                }
            }

            link.set_operation(pos, *operation)?;
            link.set_block(pos, &value[full_block_number * BLOCK_LENGTH..], true)?;
            pos += 1;
            if pos == LINE_LENGTH {
                chain.push(link);
                link = Link::new();
                pos = 0
            }
        }

        // Don't forget the last line if some blocks were written to it.
        if pos != 0 {
            chain.push(link);
        }

        Ok(chain)
    }

    /// Recomposes the given sequence of Chain Table values into Findex values.
    /// No duplicated and no deleted value is returned.
    ///
    /// # Description
    ///
    /// Iterates over the blocks:
    /// - stacks the blocks until reading a terminating block;
    /// - merges the data from the stacked block and fill the stack;
    /// - if this value was an addition, adds it to the set, otherwise removes
    ///   any matching value from the set.
    pub(crate) fn recompose<const BLOCK_LENGTH: usize, const LINE_LENGTH: usize>(
        &self,
        chain: &[Link],
    ) -> Result<HashSet<<Self as MmEnc<SEED_LENGTH, UserError>>::Item>, Error<UserError>> {
        // Allocate an upper bound on the number of values.
        let mut indexed_values = HashSet::with_capacity(chain.len() * LINE_LENGTH);
        let mut stack = Vec::new();
        let mut current_operation = None;

        for ct_value in chain.iter() {
            for pos in 0..LINE_LENGTH {
                let (is_terminating, data) = ct_value.get_block(pos)?;
                let operation = ct_value.get_operation(pos)?;

                if current_operation.is_some() && current_operation.as_ref() != Some(&operation) {
                    return Err(Error::<UserError>::Crypto(
                        "findex value cannot be decomposed into blocks with different operations"
                            .to_string(),
                    ));
                }

                if is_terminating {
                    let mut findex_value =
                        Vec::with_capacity(stack.len() * BLOCK_LENGTH + data.len());
                    for block_data in stack {
                        findex_value.extend(block_data);
                    }
                    findex_value.extend(data);

                    if Operation::Addition == operation {
                        indexed_values.insert(findex_value);
                    } else {
                        indexed_values.remove(&findex_value);
                    }

                    current_operation = None;
                    stack = Vec::new();
                } else {
                    stack.push(data);
                    if current_operation.is_none() {
                        current_operation = Some(operation);
                    }
                }
            }
        }
        Ok(indexed_values)
    }

    /// Derives the chain metadata from the given entry:
    /// - the chain key
    /// - the chain tokens
    pub(crate) fn derive_metadata(
        &self,
        entry: &Entry<ChainTable>,
    ) -> (ChainTable::Key, Vec<ChainTable::Token>) {
        let chain_key = self.chain_table.derive_keys(&entry.seed);
        let chain_tokens = entry
            .chain_token
            .as_ref()
            .map(|last_token| self.unroll(&chain_key, &entry.tag_hash, last_token))
            .unwrap_or_default();
        (chain_key, chain_tokens)
    }
}

#[async_trait(?Send)]
impl<
        UserError: CallbackErrorTrait,
        EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>>,
        ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
    > MmEnc<SEED_LENGTH, UserError> for FindexMultiMap<UserError, EntryTable, ChainTable>
{
    type Error = Error<UserError>;
    type Item = Vec<u8>;
    type Key = EntryTable::Key;
    type Seed = EntryTable::Seed;

    fn gen_seed(&self, rng: &mut impl CryptoRngCore) -> Self::Seed {
        self.entry_table.gen_seed(rng)
    }

    fn derive_keys(&self, seed: &Self::Seed) -> Self::Key {
        self.entry_table.derive_keys(seed)
    }

    async fn get<Tag: Send + Sync + Debug + Hash + Eq + AsRef<[u8]>>(
        &self,
        key: &Self::Key,
        tags: HashSet<Tag>,
        label: &Label,
    ) -> Result<HashMap<Tag, HashSet<Self::Item>>, Self::Error> {
        let entries = self.fetch_entries_by_tag(key, tags, label).await?;

        let chain_metadata = entries
            .into_iter()
            .map(|(tag, entry)| (tag, self.derive_metadata(&entry)))
            .collect::<Vec<_>>();

        let links = self
            .chain_table
            .get(
                chain_metadata
                    .iter()
                    .flat_map(|(_, (_, tokens))| tokens)
                    .copied()
                    .collect(),
            )
            .await?
            .into_iter()
            .collect::<HashMap<_, _>>();

        let mut indexed_values =
            HashMap::<Tag, HashSet<Self::Item>>::with_capacity(chain_metadata.len());

        for (tag, (chain_key, chain_tokens)) in chain_metadata {
            let chain_links = chain_tokens
                .iter()
                .filter_map(|token| links.get(token))
                .map(|ciphertext| self.chain_table.resolve(&chain_key, ciphertext).map(Link))
                .collect::<Result<Vec<_>, _>>()?;

            indexed_values
                .entry(tag)
                .or_default()
                .extend(self.recompose::<BLOCK_LENGTH, LINE_WIDTH>(&chain_links)?);
        }
        Ok(indexed_values)
    }

    async fn insert<Tag: Send + Sync + Hash + Eq + AsRef<[u8]>>(
        &mut self,
        rng: Arc<Mutex<impl Send + Sync + CryptoRngCore>>,
        key: &Self::Key,
        modifications: HashMap<Tag, Vec<(Operation, Self::Item)>>,
        label: &Label,
    ) -> Result<HashSet<Tag>, Self::Error> {
        let mut token_to_tag = HashMap::with_capacity(modifications.len());
        let mut chain_values = HashMap::with_capacity(modifications.len());
        for (tag, chain) in modifications {
            let mut tag_hash = [0; HASH_LENGTH];
            let mut hasher = Sha3::v256();
            hasher.update(tag.as_ref());
            hasher.finalize(&mut tag_hash);
            let entry_token = self.entry_table.tokenize(key, &tag_hash, Some(label));

            token_to_tag.insert(entry_token, tag);
            chain_values.insert(
                tag_hash,
                (
                    entry_token,
                    self.decompose::<BLOCK_LENGTH, LINE_WIDTH>(&chain)?,
                ),
            );
        }

        // 1. Upsert Entry Table values associated to the chains into which new values
        //    are to be inserted.
        let old_entries = self
            .entry_table
            .get(
                chain_values
                    .values()
                    .map(|(et_token, _)| et_token)
                    .copied()
                    .collect(),
            )
            .await?;

        let n_entries = old_entries.len();
        let old_entries = old_entries.into_iter().try_fold(
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

        let new_tags = token_to_tag
            .into_iter()
            .filter(|(token, _)| !old_entries.contains_key(token))
            .map(|(_, tag)| tag)
            .collect();

        let mut chain = HashMap::with_capacity(chain_values.len());
        let mut new_entries = HashMap::with_capacity(chain_values.len());
        for (tag_hash, (entry_token, chain_links)) in &chain_values {
            let mut entry = if let Some(ciphertext) = old_entries.get(entry_token) {
                Entry::<ChainTable>::from(self.entry_table.resolve(key, ciphertext)?)
            } else {
                Entry {
                    seed: self
                        .chain_table
                        .gen_seed(&mut *rng.lock().expect("could not lock mutex")),
                    tag_hash: *tag_hash,
                    chain_token: None,
                }
            };

            let chain_key = self.chain_table.derive_keys(&entry.seed);
            let chain_tokens = self.derive_chain_tokens(
                &chain_key,
                entry.chain_token.unwrap_or_else(|| entry.tag_hash.into()),
                chain_links.len(),
            )?;
            entry.chain_token = chain_tokens.last().copied();

            chain.insert(*tag_hash, (chain_key, chain_tokens));
            new_entries.insert(
                *entry_token,
                self.entry_table.prepare(
                    &mut *rng.lock().expect("could not lock mutex"),
                    key,
                    entry.into(),
                )?,
            );
        }

        // 2 - Upsert modifications to the Entry Table.
        let mut old_entries = self.entry_table.upsert(&old_entries, new_entries).await?;

        // Retry until all modifications are upserted.
        while !old_entries.is_empty() {
            new_entries = HashMap::with_capacity(old_entries.len());
            for (tag_hash, (entry_token, chain_links)) in &chain_values {
                if let Some(ciphertext) = old_entries.get(entry_token) {
                    let mut entry =
                        Entry::<ChainTable>::from(self.entry_table.resolve(key, ciphertext)?);

                    let chain_key = self.chain_table.derive_keys(&entry.seed);
                    let chain_tokens = self.derive_chain_tokens(
                        &chain_key,
                        entry.chain_token.unwrap_or_else(|| entry.tag_hash.into()),
                        chain_links.len(),
                    )?;
                    entry.chain_token = chain_tokens.last().copied();

                    let encrypted_entry = self.entry_table.prepare(
                        &mut *rng.lock().expect("could not lock mutex"),
                        key,
                        entry.into(),
                    )?;

                    if let Some(e) = chain.get_mut(tag_hash) {
                        *e = (chain_key, chain_tokens);
                    }

                    if let Some(e) = new_entries.get_mut(entry_token) {
                        *e = encrypted_entry;
                    }
                }
            }

            old_entries = self.entry_table.upsert(&old_entries, new_entries).await?;
        }

        let mut encrypted_links =
            HashMap::with_capacity(chain_values.values().map(|(_, v)| v.len()).sum());
        for (tag_hash, (_, chain_links)) in chain_values {
            let (chain_key, new_tokens) = chain.remove(&tag_hash).ok_or_else(|| {
                CoreError::Crypto(
                    "Chain Table tags were generated for all findex tokens.".to_string(),
                )
            })?;

            if chain_links.len() != new_tokens.len() {
                return Err(CoreError::Crypto(format!(
                    "{} new tags were generated when {} new Chain Table values are to be inserted",
                    new_tokens.len(),
                    chain_links.len()
                ))
                .into());
            }

            let rng = &mut *rng.lock().expect("could not lock mutex");
            let encrypted_chain_links = new_tokens
                .into_iter()
                .zip(chain_links)
                .map(|(token, value)| {
                    self.chain_table
                        .prepare(rng, &chain_key, value.0)
                        .map(|ciphertext| (token, ciphertext))
                })
                .collect::<Result<HashMap<_, _>, _>>()?;
            encrypted_links.extend(encrypted_chain_links);
        }

        self.chain_table.insert(encrypted_links).await?;

        Ok(new_tags)
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };

    use super::*;
    use crate::edx::{chain_table::ChainTable, entry_table::EntryTable, in_memory::InMemoryEdx};

    #[actix_rt::test]
    async fn test_decompose_recompose() {
        let mut rng = CsRng::from_entropy();

        let entry_table = EntryTable::setup(InMemoryEdx::default());
        let chain_table = ChainTable::setup(InMemoryEdx::default());
        let findex = FindexMultiMap::new(entry_table, chain_table);

        let n = 10;
        let mut values = HashSet::with_capacity(n);
        for _ in 0..n {
            let mut v = vec![0; 32];
            rng.fill_bytes(&mut v);
            values.insert(v);
        }

        let lines = findex
            .decompose::<BLOCK_LENGTH, LINE_WIDTH>(
                &values
                    .iter()
                    .map(|v| (Operation::Addition, v.clone()))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let res = findex
            .recompose::<BLOCK_LENGTH, LINE_WIDTH>(&lines)
            .unwrap();
        assert_eq!(values, res);
    }
}
