//! Findex SSE scheme.
//!
//! This scheme uses one EDX in order to store chain metadata:
//! - a seed used to derive the chain keys
//! - a hash used to derive the EDX token for this value
//! - a counter
//!
//! The counter is used to count the number of lines in the EMM associated to
//! this chain. Indeed, each time an push is performed, a new line is created.
//! This avoids race condition when applying modifications on the two tables.
//!
//! This scheme uses one EMM in order to store the chain data. Each chain is
//! encrypted using its own key. The tokens can be derived from the counter
//! values and its one token key.

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
};

use cosmian_crypto_core::symmetric_crypto::{aes_256_gcm_pure::KEY_LENGTH, key::Key};

use crate::{
    chain_table::ChainTable,
    edx::Edx,
    entry_table::EntryTable,
    error::Error,
    parameters::{HASH_LENGTH, SEED_LENGTH, TOKEN_LENGTH},
};

#[derive(Debug)]
pub enum Operation {
    Addition,
    Deletion,
}

const ENTRY_TABLE_VALUE_LENGTH: usize = SEED_LENGTH + HASH_LENGTH + 4;

pub struct EntryTableValue<'a>(&'a [u8; ENTRY_TABLE_VALUE_LENGTH]);

impl<'a> EntryTableValue<'a> {
    pub fn seed(&self) -> &[u8] {
        &self.0[..SEED_LENGTH]
    }

    pub fn hash(&self) -> &[u8] {
        &self.0[SEED_LENGTH..SEED_LENGTH + HASH_LENGTH]
    }

    pub fn counter(&self) -> u32 {
        let mut counter = [0; 4];
        counter.copy_from_slice(&self.0[SEED_LENGTH + HASH_LENGTH..]);
        u32::from_be_bytes(counter)
    }
}

pub struct Findex<
    const BLOCK_LENGTH: usize,
    const LINE_LENGTH: usize,
    CallbackError: std::error::Error,
> where
    [(); BLOCK_LENGTH * LINE_LENGTH]: Sized,
{
    // Findex Entry Table is used to store:
    // - a seed
    // - a hash
    // - a counter (an u32)
    entry_table: EntryTable<ENTRY_TABLE_VALUE_LENGTH, CallbackError>,
    chain_table: ChainTable<BLOCK_LENGTH, LINE_LENGTH, CallbackError>,
}

impl<const BLOCK_LENGTH: usize, const LINE_LENGTH: usize, CallbackError: std::error::Error>
    Findex<BLOCK_LENGTH, LINE_LENGTH, CallbackError>
where
    [(); BLOCK_LENGTH * LINE_LENGTH]: Sized,
{
    /// Derives all tags used to index the Entry Table from the given
    /// initialization value and counter.
    ///
    /// Tags simply are the values between the initialization value and the
    /// counter.
    fn unroll(init: usize, counter: usize) -> std::ops::Range<usize> {
        init..init + counter
    }

    /// Walks through the given graph from the given entry. Returns the set of
    /// values found during the walk.
    ///
    /// In order not to enter cycles, the same node is not visited twice. This
    /// is ensured by maintaining a set of visited nodes.
    fn walk<'a, Tag: Hash + Eq, IndexedValue: Clone>(
        graph: &HashMap<Tag, HashSet<IndexedValue>>,
        entry: &'a Tag,
        visited: &mut HashSet<&'a Tag>,
    ) -> HashSet<IndexedValue> {
        if visited.contains(&entry) {
            // Results associated to this tag have already been recovered.
            return HashSet::new();
        } else {
            visited.insert(entry);
        }

        let indexed_values = match graph.get(entry) {
            Some(values) => values,
            None => return HashSet::new(),
        };

        for value in indexed_values {
            // If the value is a Location, add it to the results
            // else, recurse on this next tag
        }

        todo!()
    }

    /// Push the given modifications to the indexes using the given key.
    ///
    /// Modifications list for each tag, a set of indexed value with the
    /// associated operation to perform on the indexes. Operations can be
    /// additions or deletions.
    ///
    /// *Note*: only one operation per indexed value and per tag can be applied
    /// per push.
    fn push<IndexedValue: Hash + Eq, Tag: Hash + Eq>(
        k: &Key<SEED_LENGTH>,
        items: HashMap<Tag, HashMap<IndexedValue, Operation>>,
    ) {
        todo!()
    }

    /// Derives Findex master key using the given seed.
    pub fn derive_key(
        &self,
        seed: &Key<SEED_LENGTH>,
    ) -> <EntryTable<ENTRY_TABLE_VALUE_LENGTH, CallbackError> as Edx<
        KEY_LENGTH,
        TOKEN_LENGTH,
        ENTRY_TABLE_VALUE_LENGTH,
        Error<CallbackError>,
    >>::Key {
        self.entry_table.derive_key(seed)
    }

    /// Searches indexes for the given tags using the given key.
    pub fn search<Tag: Clone + Debug + Hash + Eq + AsRef<[u8]>, IndexedValue: Clone>(
        &self,
        k: &<EntryTable<ENTRY_TABLE_VALUE_LENGTH, CallbackError> as Edx<
            KEY_LENGTH,
            TOKEN_LENGTH,
            ENTRY_TABLE_VALUE_LENGTH,
            Error<CallbackError>,
        >>::Key,
        tags: HashSet<Tag>,
    ) -> Result<!, Error<CallbackError>> {
        let graph = HashMap::<Tag, HashSet<IndexedValue>>::with_capacity(tags.len());

        while !tags.is_empty() {
            let et_tokens = tags
                .iter()
                .map(|tag| (tag.clone(), self.entry_table.tokenize(k, tag.as_ref())))
                .collect::<HashMap<_, _>>();
            let et_values = self
                .entry_table
                .get(et_tokens.values().cloned().collect())?
                .into_iter()
                .map(|(token, value)| -> Result<_, _> {
                    Ok((token, self.entry_table.resolve(k, value)?))
                })
                .collect::<Result<HashMap<_, _>, Error<CallbackError>>>()?;

            let mut ct_tokens = HashMap::<Tag, Vec<_>>::with_capacity(et_values.len());
            let mut ct_keys = HashMap::with_capacity(et_values.len());

            for tag in &tags {
                let token = et_tokens.get(tag).ok_or_else(|| {
                    Error::CryptoError(format!("no token for the given tag: {tag:?}"))
                })?;
                if let Some(value) = et_values.get(token) {
                    let value = EntryTableValue(value);
                    let k_ct: crate::edx::EdxKey<KEY_LENGTH> =
                        self.chain_table.derive_key(value.seed());

                    ct_tokens.entry(tag.clone()).or_default().extend(
                        Self::unroll(0, value.counter() as usize)
                            .map(|ct_tag| self.chain_table.tokenize(&k_ct, &ct_tag.to_be_bytes())),
                    );

                    ct_keys.insert(tag.clone(), k_ct);
                }
            }
        }
        todo!()
    }

    /// Adds the given values to the index for the associater tags.
    pub fn add<IndexedValue: Hash + Eq + Clone, Tag: Hash + Eq>(
        k: &Key<SEED_LENGTH>,
        items: HashMap<IndexedValue, HashSet<Tag>>,
    ) {
        let mut pushed_items = HashMap::<Tag, HashMap<IndexedValue, Operation>>::new();
        for (indexed_value, tags) in items {
            for tag in tags {
                pushed_items
                    .entry(tag)
                    .or_default()
                    .insert(indexed_value.clone(), Operation::Addition);
            }
        }
        Self::push(k, pushed_items)
    }

    /// Removes the given values from the index for the associater tags.
    pub fn remove<IndexedValue: Hash + Eq + Clone, Tag: Hash + Eq>(
        k: &Key<SEED_LENGTH>,
        items: HashMap<IndexedValue, HashSet<Tag>>,
    ) {
        let mut pushed_items = HashMap::<Tag, HashMap<IndexedValue, Operation>>::new();
        for (indexed_value, tags) in items {
            for tag in tags {
                pushed_items
                    .entry(tag)
                    .or_default()
                    .insert(indexed_value.clone(), Operation::Deletion);
            }
        }
        Self::push(k, pushed_items)
    }
}
