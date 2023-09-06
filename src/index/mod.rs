//! Easy to use `Index` interface for `Findex` that hides most cryptographic
//! details.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;

use crate::{
    edx::TokenDump,
    findex_graph::{FindexGraph, GxEnc},
    findex_mm::{Operation, ENTRY_LENGTH, LINK_LENGTH},
    parameters::USER_KEY_LENGTH,
    CallbackErrorTrait, DxEnc, Error, IndexedValue,
};

mod structs;

use cosmian_crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng, RandomFixedSizeCBytes, SecretCBytes, SymmetricKey,
};
pub use structs::{Keyword, Label, Location};

#[async_trait]
pub trait DbCallback {
    type Error: CallbackErrorTrait;

    /// Returns the locations that are still in use among the ones given.
    async fn filter_removed_locations(
        &self,
        locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, Self::Error>;
}

#[async_trait]
pub trait Index<EntryTable: DxEnc<ENTRY_LENGTH>, ChainTable: DxEnc<LINK_LENGTH>> {
    /// Index key.
    type Key: SecretCBytes<{ USER_KEY_LENGTH }>;

    /// Index error type.
    type Error: std::error::Error + Sync + Send;

    /// Instantiates a new index.
    fn new(et: EntryTable, ct: ChainTable) -> Self;

    /// Generates a new random cryptographic key.
    fn keygen(&self) -> Self::Key;

    /// Searches the index for the given keywords.
    ///
    /// The `interrupt` callback is fed with the results of each graph search
    /// iteration. Iterations are stopped if the `interrupt` return `true`.
    async fn search<
        F: Send + Sync + Future<Output = bool>,
        Interrupt: Send + Sync + Fn(HashMap<Keyword, HashSet<IndexedValue<Keyword, Location>>>) -> F,
    >(
        &self,
        key: &Self::Key,
        label: &Label,
        keywords: HashSet<Keyword>,
        interrupt: &Interrupt,
    ) -> Result<HashMap<Keyword, HashSet<Location>>, Self::Error>;

    /// Indexes the given `IndexedValue`s for the given `Keyword`s. Returns the
    /// set of keywords added to the index.
    async fn add(
        &mut self,
        key: &Self::Key,
        label: &Label,
        keywords: HashMap<IndexedValue<Keyword, Location>, HashSet<Keyword>>,
    ) -> Result<HashSet<Keyword>, Self::Error>;

    /// Removes the indexing of the given `IndexedValue`s for the given
    /// `Keyword`s. Returns the set of keywords added to the index.
    async fn delete(
        &mut self,
        key: &Self::Key,
        label: &Label,
        keywords: HashMap<IndexedValue<Keyword, Location>, HashSet<Keyword>>,
    ) -> Result<HashSet<Keyword>, Self::Error>;
}

#[derive(Debug)]
pub struct Findex<
    UserError: CallbackErrorTrait,
    EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>>,
    ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
> {
    pub findex_graph: FindexGraph<UserError, EntryTable, ChainTable>,
    rng: Arc<Mutex<CsRng>>,
}

#[async_trait]
impl<
        UserError: CallbackErrorTrait,
        EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>>,
        ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
    > Index<EntryTable, ChainTable> for Findex<UserError, EntryTable, ChainTable>
{
    type Error = Error<UserError>;
    type Key = SymmetricKey<{ USER_KEY_LENGTH }>;

    fn new(et: EntryTable, ct: ChainTable) -> Self {
        Self {
            findex_graph: FindexGraph::new(et, ct),
            rng: Arc::new(Mutex::new(CsRng::from_entropy())),
        }
    }

    fn keygen(&self) -> Self::Key {
        Self::Key::new(&mut *self.rng.lock().expect("could not lock mutex"))
    }

    async fn search<
        F: Send + Sync + Future<Output = bool>,
        Interrupt: Send + Sync + Fn(HashMap<Keyword, HashSet<IndexedValue<Keyword, Location>>>) -> F,
    >(
        &self,
        key: &Self::Key,
        label: &Label,
        keywords: HashSet<Keyword>,
        interrupt: &Interrupt,
    ) -> Result<HashMap<Keyword, HashSet<Location>>, Self::Error> {
        let mut seed =
            <FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Seed::default();
        seed.as_mut().copy_from_slice(key.as_bytes());
        let key = self.findex_graph.derive_keys(&seed);
        let graph = self
            .findex_graph
            .get(&key, keywords.clone(), label, interrupt)
            .await?;

        let mut res = HashMap::with_capacity(keywords.len());
        for tag in keywords {
            let indexed_values = self.findex_graph.walk(&graph, &tag, &mut HashSet::new());
            res.insert(tag, indexed_values);
        }
        Ok(res)
    }

    async fn add(
        &mut self,
        key: &Self::Key,
        label: &Label,
        keywords: HashMap<IndexedValue<Keyword, Location>, HashSet<Keyword>>,
    ) -> Result<HashSet<Keyword>, Self::Error> {
        let mut seed =
            <FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Seed::default();
        seed.as_mut().copy_from_slice(key.as_bytes());
        let key = self.findex_graph.derive_keys(&seed);

        let mut modifications = HashMap::<_, Vec<_>>::new();
        for (value, keywords) in keywords {
            for keyword in keywords {
                modifications
                    .entry(keyword)
                    .or_default()
                    .push((Operation::Addition, value.clone()));
            }
        }

        self.findex_graph
            .insert(self.rng.clone(), &key, modifications, label)
            .await
    }

    async fn delete(
        &mut self,
        key: &Self::Key,
        label: &Label,
        keywords: HashMap<IndexedValue<Keyword, Location>, HashSet<Keyword>>,
    ) -> Result<HashSet<Keyword>, Self::Error> {
        let mut seed =
            <FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Seed::default();
        seed.as_mut().copy_from_slice(key.as_bytes());
        let key = self.findex_graph.derive_keys(&seed);

        let mut modifications = HashMap::<_, Vec<_>>::new();
        for (value, keywords) in keywords {
            for keyword in keywords {
                modifications
                    .entry(keyword)
                    .or_default()
                    .push((Operation::Deletion, value.clone()));
            }
        }

        self.findex_graph
            .insert(self.rng.clone(), &key, modifications, label)
            .await
    }
}

impl<
        UserError: CallbackErrorTrait,
        EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>>
            + TokenDump<Token = <EntryTable as DxEnc<ENTRY_LENGTH>>::Token, Error = Error<UserError>>,
        ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
    > Findex<UserError, EntryTable, ChainTable>
{
    /// Number of items to compact at once.
    ///
    /// Given that an entry is EB bytes long and that a link is LB bytes long,
    /// the memory used by the compact operation is:
    ///
    /// N * 32 + BS * EB + f * BS * LB
    pub const COMPACT_BATCH_SIZE: usize = 1_000_000;

    /// Draw `n` tokens at random among the given `tokens`. The same token may
    /// be drawn several times, thus the number of tokens returned may be
    /// lower than `n`.
    ///
    /// TODO: update the formula used to select the number of lines to compact.
    fn select_random_tokens(
        &self,
        n: usize,
        tokens: &[<EntryTable as DxEnc<ENTRY_LENGTH>>::Token],
    ) -> HashSet<<EntryTable as DxEnc<ENTRY_LENGTH>>::Token> {
        if tokens.len() <= n {
            return tokens.iter().cloned().collect();
        }

        let mut rng = self.rng.lock().expect("could not lock mutex");
        let mut res = HashSet::with_capacity(n);
        for _ in 0..n {
            // In order to draw a random element from the set, draw a random u64 and use it
            // modulo the length of the set. This is not perfectly uniform but should be
            // enough in practice.
            let index = (rng.next_u64() % tokens.len() as u64) as usize;
            res.insert(tokens[index]);
        }
        res
    }

    /// Returns the expected number of draws per compact operation such that all
    /// EntryTable tokens are drawn after `n_compact_to_full` such operation.
    fn get_compact_line_number(
        &self,
        entry_table_length: usize,
        n_compact_to_full: usize,
    ) -> usize {
        let length = entry_table_length as f64;
        // [Euler's gamma constant](https://en.wikipedia.org/wiki/Euler%E2%80%93Mascheroni_constant).
        const GAMMA: f64 = 0.5772;
        // Number of draws needed to get the whole batch, see the
        // [coupon collector's problem](https://en.wikipedia.org/wiki/Coupon_collector%27s_problem).
        let n_draws = 0.5 + length * (length.log2() + GAMMA);
        // Split this number among the given number of compact operations.
        (n_draws / n_compact_to_full as f64) as usize
    }

    async fn compact_batch<DbInterface: DbCallback<Error = UserError>>(
        &mut self,
        old_key: &<FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Key,
        new_key: &<FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Key,
        new_label: &Label,
        compact_target: &HashSet<<EntryTable as DxEnc<ENTRY_LENGTH>>::Token>,
        tokens: HashSet<<EntryTable as DxEnc<ENTRY_LENGTH>>::Token>,
        db_interface: &DbInterface,
    ) -> Result<(), Error<UserError>> {
        let (mut indexed_values, data) = self
            .findex_graph
            .prepare_compact::<Keyword, Location>(old_key, tokens, compact_target)
            .await?;

        let locations = indexed_values
            .values()
            .flatten()
            .filter_map(IndexedValue::get_data)
            .cloned()
            .collect();

        let remaining_locations = db_interface.filter_removed_locations(locations).await?;

        for values in indexed_values.values_mut() {
            let res = values
                .iter()
                .filter(|v| {
                    if let Some(location) = v.get_data() {
                        remaining_locations.contains(location)
                    } else {
                        true
                    }
                })
                .cloned()
                .collect();
            *values = res;
        }

        self.findex_graph
            .complete_compacting(self.rng.clone(), new_key, new_label, indexed_values, data)
            .await
    }

    /// Process the entire Entry Table by batch. Compact a random portion of
    /// the associated chains such that the Chain Table is entirely compacted
    /// after `n_compact_to_full` operations in average. A new token is
    /// generated for each entry and the entries are reencrypted using the
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
    pub async fn compact<DbInterface: DbCallback<Error = UserError>>(
        &mut self,
        old_key: &<Self as Index<EntryTable, ChainTable>>::Key,
        new_key: &<Self as Index<EntryTable, ChainTable>>::Key,
        old_label: &Label,
        new_label: &Label,
        n_compact_to_full: usize,
        db_interface: &DbInterface,
    ) -> Result<(), Error<UserError>> {
        if (old_key == new_key) && (old_label == new_label) {
            return Err(Error::Crypto(
                "both the same key and label can be used to compact".to_string(),
            ));
        }

        let mut new_seed =
            <FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Seed::default();
        new_seed.as_mut().copy_from_slice(new_key);
        //kdf256!(new_seed.as_mut(), new_label, new_key.as_ref());
        let new_key = self.findex_graph.derive_keys(&new_seed);

        let mut old_seed =
            <FindexGraph<UserError, EntryTable, ChainTable> as GxEnc<UserError>>::Seed::default();
        //kdf256!(old_seed.as_mut(), old_label, old_key.as_ref());
        old_seed.as_mut().copy_from_slice(old_key);
        let old_key = self.findex_graph.derive_keys(&old_seed);

        let entry_tokens = self.findex_graph.list_indexed_encrypted_tags().await?;

        let entries_to_compact = self.select_random_tokens(
            self.get_compact_line_number(entry_tokens.len(), n_compact_to_full),
            entry_tokens.as_slice(),
        );

        for i in 0..entry_tokens.len() / Self::COMPACT_BATCH_SIZE {
            self.compact_batch(
                &old_key,
                &new_key,
                new_label,
                &entries_to_compact,
                entry_tokens[i * Self::COMPACT_BATCH_SIZE..(i + 1) * Self::COMPACT_BATCH_SIZE]
                    .iter()
                    .cloned()
                    .collect(),
                db_interface,
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
                .cloned()
                .collect(),
            db_interface,
        )
        .await?;

        Ok(())
    }
}
