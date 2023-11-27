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
    edx::{DxEnc, Token},
    error::Error,
    findex_mm::{
        structs::{Entry, Link, Operation},
        FindexMultiMap, MmEnc, ENTRY_LENGTH, LINK_LENGTH,
    },
    parameters::{BLOCK_LENGTH, HASH_LENGTH, LINE_WIDTH, SEED_LENGTH},
    BackendErrorTrait, CoreError, Label,
};

impl<
        UserError: BackendErrorTrait,
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
        last_token: &Token,
    ) -> Vec<Token> {
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
        mut last_token: Token,
        n: usize,
    ) -> Vec<Token> {
        let mut res = Vec::with_capacity(n);
        for _ in 0..n {
            let new_token = self.chain_table.tokenize(ct_key, &last_token, None);
            res.push(new_token);
            last_token = new_token;
        }
        res
    }

    /// Fetches the entries associated to the given tags.
    async fn fetch_entries_by_tag<Tag: Hash + Clone + Eq + AsRef<[u8]>>(
        &self,
        key: &EntryTable::Key,
        tags: HashSet<Tag>,
        label: &Label,
    ) -> Result<Vec<(Tag, Entry<ChainTable>)>, Error<UserError>> {
        let tokens = tags
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
            .filter_map(|(token, entry)| tokens.get(&token).cloned().map(|tag| (tag, entry)))
            .collect())
    }

    /// Fetches the Entry Table for the given tokens and decrypts the entries
    /// using the given key.
    pub(crate) async fn fetch_entries(
        &self,
        key: &EntryTable::Key,
        tokens: HashSet<Token>,
    ) -> Result<Vec<(Token, Entry<ChainTable>)>, Error<UserError>> {
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
    ) -> Result<Vec<Link>, CoreError> {
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
                    pos = 0;
                }
            }

            link.set_operation(pos, *operation)?;
            link.set_block(pos, &value[full_block_number * BLOCK_LENGTH..], true)?;
            pos += 1;
            if pos == LINE_LENGTH {
                chain.push(link);
                link = Link::new();
                pos = 0;
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
    // TODO (TBZ): take an iterator as input to avoid needless collections.
    pub(crate) fn recompose<const BLOCK_LENGTH: usize, const LINE_LENGTH: usize>(
        &self,
        chain: &[Link],
    ) -> Result<HashSet<<Self as MmEnc<SEED_LENGTH, UserError>>::Item>, CoreError> {
        // Allocate an upper bound on the number of values.
        let mut indexed_values = HashSet::with_capacity(chain.len() * LINE_LENGTH);
        let mut stack = Vec::new();
        let mut current_operation = None;

        for ct_value in chain {
            for pos in 0..LINE_LENGTH {
                let (is_terminating, data) = ct_value.get_block(pos)?;
                let operation = ct_value.get_operation(pos)?;

                if current_operation.is_some() && current_operation.as_ref() != Some(&operation) {
                    return Err(CoreError::Crypto(
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
    ) -> (ChainTable::Key, Vec<Token>) {
        let chain_key = self.chain_table.derive_keys(&entry.seed);
        let chain_tokens = entry
            .chain_token
            .as_ref()
            .map(|last_token| self.unroll(&chain_key, &entry.tag_hash, last_token))
            .unwrap_or_default();
        (chain_key, chain_tokens)
    }

    /// Commits the given chain modifications into the Entry Table.
    ///
    /// Returns the chains to insert in the Chain Table.
    async fn commit<Tag: Clone + Hash + Eq + AsRef<[u8]>>(
        &self,
        rng: Arc<Mutex<impl CryptoRngCore>>,
        key: &EntryTable::Key,
        label: &Label,
        chain_additions: &HashMap<Tag, Vec<Link>>,
    ) -> Result<(HashSet<Tag>, HashMap<Tag, (ChainTable::Key, Vec<Token>)>), Error<UserError>> {
        // Compute the token associated to the modifications.
        let mut chain_additions = chain_additions
            .iter()
            .map(|(tag, links)| {
                let mut tag_hash = [0; HASH_LENGTH];
                let mut hasher = Sha3::v256();
                hasher.update(tag.as_ref());
                hasher.finalize(&mut tag_hash);
                (
                    tag,
                    (
                        self.entry_table.tokenize(key, &tag_hash, Some(label)),
                        tag_hash,
                        links.len(),
                    ),
                )
            })
            .collect::<HashMap<_, _>>();

        let encrypted_entries = self
            .entry_table
            .get(
                chain_additions
                    .values()
                    .map(|(token, _, _)| token)
                    .copied()
                    .collect(),
            )
            .await?;

        // Assert only one old entry is found per token.
        let mut encrypted_entries = encrypted_entries.into_iter().try_fold(
            HashMap::with_capacity(chain_additions.len()),
            |mut acc, (k, v)| {
                let old_value = acc.insert(k, v);
                if old_value.is_some() {
                    Err(CoreError::Crypto(
                        "multiple Entry Table values are not allowed in upsert mode".to_string(),
                    ))
                } else {
                    Ok(acc)
                }
            },
        )?;

        let mut new_tags = HashSet::with_capacity(chain_additions.len());
        let mut chain = HashMap::with_capacity(chain_additions.len());

        while !chain_additions.is_empty() {
            let mut new_entries = HashMap::with_capacity(chain_additions.len());
            // Compute new chain tokens to insert modifications and update the associated
            // entry. Create one if the associated tag was not indexed yet.
            for (tag, (token, tag_hash, n_additions)) in &chain_additions {
                let mut entry = if let Some(ciphertext) = encrypted_entries.get(token) {
                    Entry::<ChainTable>::from(self.entry_table.resolve(key, ciphertext)?)
                } else {
                    // This tag is not indexed yet in the Entry table.
                    new_tags.insert((*tag).clone());
                    Entry {
                        seed: self
                            .chain_table
                            .gen_seed(&mut *rng.lock().expect("could not lock mutex")),
                        tag_hash: *tag_hash,
                        chain_token: None,
                    }
                };

                // TODO: a cache could be added to prevent computing the key at each loop
                // iteration.
                let chain_key = self.chain_table.derive_keys(&entry.seed);

                let chain_tokens = self.derive_chain_tokens(
                    &chain_key,
                    entry.chain_token.unwrap_or_else(|| entry.tag_hash.into()),
                    *n_additions,
                );
                entry.chain_token = chain_tokens.last().copied();

                chain.insert((*tag).clone(), (chain_key, chain_tokens));
                new_entries.insert(
                    *token,
                    self.entry_table.prepare(
                        &mut *rng.lock().expect("could not lock mutex"),
                        key,
                        entry.into(),
                    )?,
                );
            }

            // 2 - Upsert new entries to the Entry Table.
            encrypted_entries = self
                .entry_table
                .upsert(encrypted_entries, new_entries)
                .await?;
            chain_additions.retain(|_, (k, _, _)| encrypted_entries.contains_key(k));
            new_tags.retain(|tag| !chain_additions.contains_key(tag));
        }

        Ok((new_tags, chain))
    }
}

#[async_trait(?Send)]
impl<
        UserError: BackendErrorTrait,
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

    async fn get<Tag: Debug + Clone + Hash + Eq + AsRef<[u8]>>(
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

    async fn insert<Tag: Clone + Hash + Eq + AsRef<[u8]>>(
        &self,
        rng: Arc<Mutex<impl CryptoRngCore>>,
        key: &Self::Key,
        modifications: HashMap<Tag, Vec<(Operation, Self::Item)>>,
        label: &Label,
    ) -> Result<HashSet<Tag>, Self::Error> {
        let chain_additions = modifications
            .into_iter()
            .map(|(tag, new_values)| {
                self.decompose::<BLOCK_LENGTH, LINE_WIDTH>(&new_values)
                    .map(|links| (tag, links))
            })
            .collect::<Result<HashMap<Tag, Vec<Link>>, _>>()?;

        let (new_tags, mut chain_tokens) = self
            .commit(rng.clone(), key, label, &chain_additions)
            .await?;

        let mut encrypted_links = HashMap::with_capacity(
            chain_tokens
                .values()
                .map(|(_, chain_tokens)| chain_tokens.len())
                .sum(),
        );

        for (tag, links) in chain_additions {
            let (chain_key, tokens) = chain_tokens.remove(&tag).ok_or_else(|| {
                CoreError::Crypto("no token not found for tag {tag:?}".to_string())
            })?;
            for (token, link) in tokens.into_iter().zip(links.into_iter()) {
                encrypted_links.insert(
                    token,
                    self.chain_table.prepare(
                        &mut *rng.lock().expect("could not lock mutex"),
                        &chain_key,
                        link.0,
                    )?,
                );
            }
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
    use crate::edx::{
        chain_table::ChainTable, entry_table::EntryTable, in_memory::InMemoryBackend,
    };

    #[actix_rt::test]
    async fn test_decompose_recompose() {
        let mut rng = CsRng::from_entropy();

        let entry_table = EntryTable::setup(InMemoryBackend::default());
        let chain_table = ChainTable::setup(InMemoryBackend::default());
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
