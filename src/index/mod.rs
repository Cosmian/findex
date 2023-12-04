//! Easy to use `Index` interface for `Findex` that hides most cryptographic
//! details.

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    future::Future,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use tracing::{instrument, trace};

use crate::{
    edx::{Token, TokenDump, Tokens},
    findex_graph::{FindexGraph, GxEnc},
    findex_mm::{Operation, ENTRY_LENGTH, LINK_LENGTH},
    DbInterfaceErrorTrait, DxEnc, Error, IndexedValue,
};

mod structs;

use cosmian_crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng, RandomFixedSizeCBytes,
};
pub use structs::{
    Data, IndexedValueToKeywordsMap, Keyword, KeywordToDataMap, Keywords, Label, UserKey,
};

/// User-friendly interface to the Findex algorithm.
#[async_trait(?Send)]
pub trait Index<EntryTable: DxEnc<ENTRY_LENGTH>, ChainTable: DxEnc<LINK_LENGTH>> {
    /// Index error type.
    type Error: std::error::Error;

    /// Instantiates a new index.
    fn new(et: EntryTable, ct: ChainTable) -> Self;

    /// Generates a new random cryptographic key.
    fn keygen(&self) -> UserKey;

    /// Searches the index for the given keywords.
    ///
    /// The `interrupt` callback is fed with the results of each graph search
    /// iteration. Iterations are stopped if the `interrupt` returns `true`.
    async fn search<
        F: Future<Output = Result<bool, String>>,
        Interrupt: Fn(HashMap<Keyword, HashSet<IndexedValue<Keyword, Data>>>) -> F,
    >(
        &self,
        key: &UserKey,
        label: &Label,
        keywords: Keywords,
        interrupt: &Interrupt,
    ) -> Result<KeywordToDataMap, Self::Error>;

    /// Adds the given associations to the index.
    ///
    /// Returns the set of keywords added as new keys to the index.
    async fn add(
        &self,
        key: &UserKey,
        label: &Label,
        associations: IndexedValueToKeywordsMap,
    ) -> Result<Keywords, Self::Error>;

    /// Removes the given associations from the index.
    ///
    /// This operation actually adds the negation of the given associations to the index,
    /// effectively increasing the index size. The compact operation is in charge of removing
    /// associations that have been negated.
    ///
    /// Returns the set of keywords added as new keys to the index.
    async fn delete(
        &self,
        key: &UserKey,
        label: &Label,
        associations: IndexedValueToKeywordsMap,
    ) -> Result<Keywords, Self::Error>;

    /// Compacts a portion of the index.
    ///
    /// It re-encrypts the entire Entry Table which allows to reset the knowledge of the index
    /// acquired by an attacker. To this effect at least either the key or the label needs to be
    /// changed.
    ///
    /// It partially compacts and re-encrypts the Chain Table. The compacting operation:
    /// - removes duplicated associations;
    /// - removes deleted associations;
    /// - removes obsolete indexed data;
    /// - ensures the padding is minimal.
    ///
    /// The `data_filter` is called with batches of the data read from the index. Only the data
    /// returned by it is indexed back.
    ///
    /// The entire index is statistically guaranteed to be compacted after calling this operation
    /// `n_compact_to_full` times. For example, if one is passed, the entire index will be
    /// compacted at once. If ten is passed, the entire index should have been compacted after the
    /// tenth call.
    async fn compact<
        F: Future<Output = Result<HashSet<Data>, String>>,
        Filter: Fn(HashSet<Data>) -> F,
    >(
        &self,
        old_key: &UserKey,
        new_key: &UserKey,
        old_label: &Label,
        new_label: &Label,
        compacting_rate: f64,
        data_filter: &Filter,
    ) -> Result<(), Self::Error>;
}

/// Findex type implements the Findex algorithm.
#[derive(Debug)]
pub struct Findex<
    UserError: DbInterfaceErrorTrait,
    EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>>,
    ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
> {
    pub findex_graph: FindexGraph<UserError, EntryTable, ChainTable>,
    rng: Arc<Mutex<CsRng>>,
}

#[async_trait(?Send)]
impl<
        UserError: DbInterfaceErrorTrait,
        EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>> + TokenDump<Error = Error<UserError>>,
        ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
    > Index<EntryTable, ChainTable> for Findex<UserError, EntryTable, ChainTable>
{
    type Error = Error<UserError>;

    fn new(et: EntryTable, ct: ChainTable) -> Self {
        Self {
            findex_graph: FindexGraph::new(et, ct),
            rng: Arc::new(Mutex::new(CsRng::from_entropy())),
        }
    }

    fn keygen(&self) -> UserKey {
        UserKey::new(&mut *self.rng.lock().expect("could not lock mutex"))
    }

    #[instrument(ret(Display), err, skip_all)]
    async fn search<
        F: Future<Output = Result<bool, String>>,
        Interrupt: Fn(HashMap<Keyword, HashSet<IndexedValue<Keyword, Data>>>) -> F,
    >(
        &self,
        key: &UserKey,
        label: &Label,
        keywords: Keywords,
        interrupt: &Interrupt,
    ) -> Result<KeywordToDataMap, Self::Error> {
        trace!("search: entering: label: {label}");
        trace!("search: entering: keywords: {keywords}");
        // TODO: avoid this copy
        let mut seed =
            <FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Seed::default();
        seed.as_mut().copy_from_slice(key.as_bytes());
        let key = self.findex_graph.derive_keys(&seed);

        let graph = self
            .findex_graph
            .get(&key, keywords.clone().into(), label, interrupt)
            .await?;

        let res = keywords
            .into_iter()
            .map(|tag| {
                let data = self.findex_graph.walk(&graph, &tag, &mut HashSet::new());
                (tag, data)
            })
            .collect();

        Ok(res)
    }

    #[instrument(ret(Display), err, skip_all)]
    async fn add(
        &self,
        key: &UserKey,
        label: &Label,
        additions: IndexedValueToKeywordsMap,
    ) -> Result<Keywords, Self::Error> {
        trace!("add: entering: label: {label}");
        trace!("add: entering: additions: {additions}");
        // TODO: avoid this copy
        let mut seed =
            <FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Seed::default();
        seed.as_mut().copy_from_slice(key.as_bytes());
        let key = self.findex_graph.derive_keys(&seed);

        let mut modifications = HashMap::<_, Vec<_>>::new();
        for (value, keywords) in additions {
            for keyword in keywords {
                modifications
                    .entry(keyword)
                    .or_default()
                    .push((Operation::Addition, value.clone()));
            }
        }

        Ok(Keywords::from(
            self.findex_graph
                .insert(self.rng.clone(), &key, modifications, label)
                .await?,
        ))
    }

    #[instrument(ret(Display), err, skip_all)]
    async fn delete(
        &self,
        key: &UserKey,
        label: &Label,
        deletions: IndexedValueToKeywordsMap,
    ) -> Result<Keywords, Self::Error> {
        trace!("delete: entering: label: {label}");
        trace!("delete: entering: deletions: {deletions}");
        // TODO: avoid this copy
        let mut seed =
            <FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Seed::default();
        seed.as_mut().copy_from_slice(key.as_bytes());
        let key = self.findex_graph.derive_keys(&seed);

        let mut modifications = HashMap::<_, Vec<_>>::new();
        for (value, keywords) in deletions {
            for keyword in keywords {
                modifications
                    .entry(keyword)
                    .or_default()
                    .push((Operation::Deletion, value.clone()));
            }
        }

        Ok(Keywords::from(
            self.findex_graph
                .insert(self.rng.clone(), &key, modifications, label)
                .await?,
        ))
    }

    /// Process the entire Entry Table by batch. Compact a random portion of
    /// the associated chains such that the Chain Table is entirely compacted
    /// after `n_compact_to_full` operations in average. A new token is
    /// generated for each entry and the entries are re-encrypted using the
    /// `new_key` and the `new_label`.
    ///
    /// A compact operation on a given chain:
    /// - fetches and decrypts the chain;
    /// - simplifies additions/deletions of the same values;
    /// - writes the chains without internal padding;
    /// - generates new keys for this chain
    /// - encrypts the new chain using the new key
    ///
    /// The size of the batches is
    /// [`COMPACT_BATCH_SIZE`](Self::COMPACT_BATCH_SIZE).
    #[instrument(ret, err, skip_all)]
    async fn compact<
        F: Future<Output = Result<HashSet<Data>, String>>,
        Filter: Fn(HashSet<Data>) -> F,
    >(
        &self,
        old_key: &UserKey,
        new_key: &UserKey,
        old_label: &Label,
        new_label: &Label,
        compacting_rate: f64,
        data_filter: &Filter,
    ) -> Result<(), Error<UserError>> {
        trace!("compact: entering: old_label: {old_label}");
        trace!("compact: entering: new_label: {new_label}");
        if (old_key == new_key) && (old_label == new_label) {
            return Err(Error::Crypto(
                "at least one from the new key or the new label should be changed during the \
                 compact operation"
                    .to_string(),
            ));
        }

        let mut new_seed =
            <FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Seed::default();
        new_seed.as_mut().copy_from_slice(new_key);
        let new_key = self.findex_graph.derive_keys(&new_seed);

        let mut old_seed =
            <FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Seed::default();
        old_seed.as_mut().copy_from_slice(old_key);
        let old_key = self.findex_graph.derive_keys(&old_seed);

        let entry_tokens = self.findex_graph.list_indexed_encrypted_tags().await?;

        let entries_to_compact = self
            .select_random_tokens(
                self.get_compact_line_number(entry_tokens.len(), compacting_rate),
                entry_tokens.as_slice(),
            )
            .into();

        for i in 0..entry_tokens.len() / Self::COMPACT_BATCH_SIZE {
            self.compact_batch(
                &old_key,
                &new_key,
                new_label,
                &entries_to_compact,
                entry_tokens[i * Self::COMPACT_BATCH_SIZE..(i + 1) * Self::COMPACT_BATCH_SIZE]
                    .iter()
                    .copied()
                    .collect(),
                data_filter,
            )
            .await?;
        }

        self.compact_batch(
            &old_key,
            &new_key,
            new_label,
            &entries_to_compact,
            entry_tokens
                [(entry_tokens.len() / Self::COMPACT_BATCH_SIZE) * Self::COMPACT_BATCH_SIZE..]
                .iter()
                .copied()
                .collect(),
            data_filter,
        )
        .await?;

        Ok(())
    }
}

impl<
        UserError: DbInterfaceErrorTrait,
        EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>> + TokenDump<Error = Error<UserError>>,
        ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
    > Findex<UserError, EntryTable, ChainTable>
{
    /// Number of items to compact at once.
    ///
    /// Given that an entry is EB bytes long and that a link is LB bytes long,
    /// the memory used by the compact operation is:
    ///
    /// N * 32 + BS * EB + f * BS * LB
    const COMPACT_BATCH_SIZE: usize = 1_000_000;

    /// Draw `n` tokens at random among the given `tokens`. The same token may
    /// be drawn several times, thus the number of tokens returned may be
    /// lower than `n`.
    ///
    /// TODO: update the formula used to select the number of lines to compact.
    fn select_random_tokens(&self, n: usize, tokens: &[Token]) -> HashSet<Token> {
        if tokens.len() <= n {
            return tokens.iter().copied().collect();
        }

        let mut rng = self.rng.lock().expect("could not lock mutex");
        let mut res = HashSet::with_capacity(n);
        for _ in 0..n {
            // In order to draw a random element from the set, draw a random `u64` and use
            // it modulo the length of the set. This is not perfectly uniform but should be
            // enough in practice.
            let index = (rng.next_u64() % tokens.len() as u64) as usize;
            res.insert(tokens[index]);
        }
        res
    }

    /// Returns the expected number of draws per compact operation such that all
    /// Entry Table tokens are drawn after `n_compact_to_full` such operation.
    fn get_compact_line_number(&self, entry_table_length: usize, compacting_rate: f64) -> usize {
        // [Euler's gamma constant](https://en.wikipedia.org/wiki/Euler%E2%80%93Mascheroni_constant).
        const GAMMA: f64 = 0.5772;

        let length = entry_table_length as f64;
        // Number of draws needed to get the whole batch, see the
        // [coupon collector's problem](https://en.wikipedia.org/wiki/Coupon_collector%27s_problem).
        let n_draws = length.mul_add(length.log2() + GAMMA, 0.5);
        // Split this number among the given number of compact operations.
        (n_draws * compacting_rate) as usize
    }

    #[instrument(ret, err, skip_all)]
    async fn compact_batch<
        F: Future<Output = Result<HashSet<Data>, String>>,
        Filter: Fn(HashSet<Data>) -> F,
    >(
        &self,
        old_key: &<FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Key,
        new_key: &<FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Key,
        new_label: &Label,
        tokens_to_compact: &Tokens,
        tokens_to_fetch: Tokens,
        data_filter: &Filter,
    ) -> Result<(), Error<UserError>> {
        trace!("compact_batch: entering: new_label: {new_label}");
        trace!("compact_batch: entering: tokens_to_compact: {tokens_to_compact}");
        trace!("compact_batch: entering: tokens_to_fetch: {tokens_to_fetch}");
        let (indexed_values, data) = self
            .findex_graph
            .prepare_compact::<Keyword, Data>(old_key, tokens_to_fetch.into(), tokens_to_compact)
            .await?;

        let indexed_data = indexed_values
            .values()
            .flatten()
            .filter_map(IndexedValue::get_data)
            .cloned()
            .collect();

        let remaining_data = data_filter(indexed_data)
            .await
            .map_err(<Self as Index<EntryTable, ChainTable>>::Error::Filter)?;

        let remaining_values = indexed_values
            .into_iter()
            .map(|(entry_token, associated_values)| {
                let remaining_values = associated_values
                    .into_iter()
                    .filter(|value| {
                        // Filter out obsolete data.
                        value
                            .get_data()
                            .map(|data| remaining_data.contains(data))
                            .unwrap_or(true)
                    })
                    .collect::<HashSet<_>>();
                (entry_token, remaining_values)
            })
            .collect::<HashMap<_, _>>();

        self.findex_graph
            .complete_compacting(self.rng.clone(), new_key, new_label, remaining_values, data)
            .await
    }
}
