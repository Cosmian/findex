//! Implement GX-Enc for `FindexGraph`.

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    future::Future,
    hash::Hash,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;

use crate::{
    findex_graph::{FindexGraph, GxEnc, IndexedValue},
    findex_mm::{FindexMultiMap, MmEnc, Operation, ENTRY_LENGTH, LINK_LENGTH},
    parameters::SEED_LENGTH,
    CallbackErrorTrait, DxEnc, Error, Label,
};

#[async_trait(?Send)]
impl<
        UserError: CallbackErrorTrait,
        EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>>,
        ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
    > GxEnc<UserError> for FindexGraph<UserError, EntryTable, ChainTable>
{
    type Error =
        <FindexMultiMap<UserError, EntryTable, ChainTable> as MmEnc<SEED_LENGTH, UserError>>::Error;
    type Key =
        <FindexMultiMap<UserError, EntryTable, ChainTable> as MmEnc<SEED_LENGTH, UserError>>::Key;
    type Seed =
        <FindexMultiMap<UserError, EntryTable, ChainTable> as MmEnc<SEED_LENGTH, UserError>>::Seed;

    fn gen_seed(&self, rng: &mut impl CryptoRngCore) -> Self::Seed {
        self.findex_mm.gen_seed(rng)
    }

    fn derive_keys(&self, seed: &Self::Seed) -> Self::Key {
        self.findex_mm.derive_keys(seed)
    }

    async fn get<
        Tag: Debug + Hash + Eq + Clone + AsRef<[u8]> + From<Vec<u8>>,
        Value: Hash + Eq + Clone + From<Vec<u8>>,
        F: Future<Output = Result<bool, String>>,
        Interrupt: Fn(HashMap<Tag, HashSet<IndexedValue<Tag, Value>>>) -> F,
    >(
        &self,
        key: &Self::Key,
        mut tags: HashSet<Tag>,
        label: &Label,
        interrupt: &Interrupt,
    ) -> Result<HashMap<Tag, HashSet<IndexedValue<Tag, Value>>>, Self::Error> {
        let mut graph = HashMap::with_capacity(tags.len());

        while !tags.is_empty() {
            let indexed_values = self.findex_mm.get(key, tags, label).await?;

            // This is needed to avoid the need to have a mutable reference to the `graph`
            // in the following `for` loop. Since having such a reference prevents calling
            // `contains_key()` (in Rust a mutable reference cannot coexist with other
            // references).
            let mut local_graph = HashMap::with_capacity(indexed_values.len());

            tags = HashSet::with_capacity(
                indexed_values
                    .values()
                    .map(std::collections::HashSet::len)
                    .sum(),
            );
            for (tag, values) in indexed_values {
                let entry = local_graph
                    .entry(tag)
                    .or_insert_with(|| HashSet::with_capacity(values.len()));
                for value in values {
                    let value = IndexedValue::<Tag, Value>::try_from(value.as_slice())?;
                    if let IndexedValue::Pointer(child) = &value {
                        if !graph.contains_key(child) {
                            // Marks the pointers to new tags to be searched at the next iteration.
                            tags.insert(child.clone());
                        }
                    }
                    entry.insert(value);
                }
            }

            let is_interrupted = interrupt(local_graph.clone())
                .await
                .map_err(Self::Error::Interrupt)?;

            if is_interrupted {
                tags = HashSet::new();
            }

            graph.extend(local_graph);
        }

        Ok(graph)
    }

    async fn insert<Tag: Clone + Hash + Eq + AsRef<[u8]>, Value: AsRef<[u8]>>(
        &self,
        rng: Arc<Mutex<impl CryptoRngCore>>,
        key: &Self::Key,
        items: HashMap<Tag, Vec<(Operation, IndexedValue<Tag, Value>)>>,
        label: &Label,
    ) -> Result<HashSet<Tag>, Error<UserError>> {
        let items = items
            .into_iter()
            .map(|(tag, modifications)| {
                let modifications = modifications
                    .into_iter()
                    .map(|(op, value)| (op, value.into()))
                    .collect();
                (tag, modifications)
            })
            .collect();

        self.findex_mm.insert(rng, key, items, label).await
    }
}

impl<
        UserError: CallbackErrorTrait,
        EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>>,
        ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
    > FindexGraph<UserError, EntryTable, ChainTable>
{
    /// Walks through the given graph from the given entry. Returns the set of
    /// values found during the walk.
    ///
    /// In order not to enter cycles, the same node is not visited twice. This
    /// is ensured by maintaining a set of visited nodes.
    #[allow(clippy::only_used_in_recursion)]
    pub fn walk<'a, Tag: Hash + Eq + Clone, Item: Clone + Hash + Eq>(
        &self,
        graph: &'a HashMap<Tag, HashSet<IndexedValue<Tag, Item>>>,
        entry: &'a Tag,
        visited: &mut HashSet<&'a Tag>,
    ) -> HashSet<Item> {
        if visited.contains(&entry) {
            // Results associated to this tag have already been recovered.
            return HashSet::new();
        }

        visited.insert(entry);

        let indexed_values = match graph.get(entry) {
            Some(values) => values,
            None => return HashSet::new(),
        };

        let mut res = HashSet::with_capacity(indexed_values.len());

        for value in indexed_values {
            match value {
                IndexedValue::Pointer(child) => res.extend(self.walk(graph, child, visited)),
                IndexedValue::Data(data) => {
                    res.insert(data.clone());
                }
            }
        }

        res
    }
}
