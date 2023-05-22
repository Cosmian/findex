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

use cosmian_crypto_core::{
    kdf,
    symmetric_crypto::{aes_256_gcm_pure::KEY_LENGTH, key::Key, SymKey},
};
use zeroize::ZeroizeOnDrop;

use crate::{
    chain_table::{self, ChainTable},
    edx::Edx,
    emm::Emm,
    entry_table::{self, EntryTable},
    error::Error,
    parameters::{HASH_LENGTH, SEED_LENGTH, TOKEN_LENGTH},
    FindexApi,
};

/// Value indexed by Findex.
///
/// This can be a data -typically a location to a document like a database UID-
/// or another tag in which case values indexed by this tag are part of the
/// results of the tag indexing it.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum IndexedValue<Tag: Clone> {
    Data(Vec<u8>),
    NextTag(Tag),
}

/// Operation allowed by Findex.
#[derive(Debug)]
enum Operation {
    Addition,
    Deletion,
}

/// Value stored in the Entry Table by Findex.
///
/// It is composed of:
/// - a seed;
/// - a hash;
/// - a counter.
const ENTRY_TABLE_VALUE_LENGTH: usize = SEED_LENGTH + HASH_LENGTH + 4;
struct EntryTableValue<'a>(&'a [u8; ENTRY_TABLE_VALUE_LENGTH]);

impl<'a> EntryTableValue<'a> {
    fn seed(&self) -> &[u8] {
        &self.0[..SEED_LENGTH]
    }

    fn hash(&self) -> &[u8] {
        &self.0[SEED_LENGTH..SEED_LENGTH + HASH_LENGTH]
    }

    fn counter(&self) -> u32 {
        let mut counter = [0; 4];
        counter.copy_from_slice(&self.0[SEED_LENGTH + HASH_LENGTH..]);
        u32::from_be_bytes(counter)
    }
}

pub struct FindexKey<
    CallbackError: std::error::Error,
    EntryTableDb: entry_table::Callbacks<TOKEN_LENGTH, ENTRY_TABLE_VALUE_LENGTH, CallbackError>,
> {
    token: Key<KEY_LENGTH>,
    entry_table: <EntryTable<ENTRY_TABLE_VALUE_LENGTH, CallbackError, EntryTableDb> as Edx<
        KEY_LENGTH,
        TOKEN_LENGTH,
        ENTRY_TABLE_VALUE_LENGTH,
        Error<CallbackError>,
    >>::Key,
}

impl<
    CallbackError: std::error::Error,
    EntryTableDb: entry_table::Callbacks<TOKEN_LENGTH, ENTRY_TABLE_VALUE_LENGTH, CallbackError>,
> ZeroizeOnDrop for FindexKey<CallbackError, EntryTableDb>
{
}

/// Value stored in the Chain Table by Findex.
///
/// It is composed of a list of:
/// - a type byte;
/// - an operation byte;
/// - a list of `LINE_LENGTH` blocks of length `BLOCK_LENGTH`.
///
/// The type byte (resp. operation byte) is used to write all the type bits
/// (resp. operation bits) into a single byte rather than adding an entire byte
/// per block.
struct ChainTableValue<const BLOCK_LENGTH: usize, const LINE_LENGTH: usize>(
    [u8; 2 + BLOCK_LENGTH * LINE_LENGTH],
)
where
    [(); 2 + BLOCK_LENGTH * LINE_LENGTH]: Sized;

impl<const BLOCK_LENGTH: usize, const LINE_LENGTH: usize> ChainTableValue<BLOCK_LENGTH, LINE_LENGTH> where
    [(); 2 + BLOCK_LENGTH * LINE_LENGTH]: Sized
{
}

pub struct Findex<
    const BLOCK_LENGTH: usize,
    const LINE_LENGTH: usize,
    CallbackError: std::error::Error,
    EntryTableDb: entry_table::Callbacks<TOKEN_LENGTH, ENTRY_TABLE_VALUE_LENGTH, CallbackError>,
    ChainTableDb: chain_table::Callbacks<TOKEN_LENGTH, { 2 + BLOCK_LENGTH * LINE_LENGTH }, CallbackError>,
> where
    [(); 2 + BLOCK_LENGTH * LINE_LENGTH]: Sized,
{
    entry_table: EntryTable<ENTRY_TABLE_VALUE_LENGTH, CallbackError, EntryTableDb>,
    chain_table: ChainTable<{ 2 + BLOCK_LENGTH * LINE_LENGTH }, CallbackError, ChainTableDb>,
}

impl<
    const BLOCK_LENGTH: usize,
    const LINE_LENGTH: usize,
    CallbackError: std::error::Error,
    EntryTableDb: entry_table::Callbacks<TOKEN_LENGTH, ENTRY_TABLE_VALUE_LENGTH, CallbackError>,
    ChainTableDb: chain_table::Callbacks<TOKEN_LENGTH, { 2 + BLOCK_LENGTH * LINE_LENGTH }, CallbackError>,
> Findex<BLOCK_LENGTH, LINE_LENGTH, CallbackError, EntryTableDb, ChainTableDb>
where
    [(); 2 + BLOCK_LENGTH * LINE_LENGTH]: Sized,
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
    fn walk<'a, Tag: Hash + Eq + Clone>(
        graph: &'a HashMap<Tag, HashSet<IndexedValue<Tag>>>,
        entry: &'a Tag,
        visited: &mut HashSet<&'a Tag>,
    ) -> HashSet<IndexedValue<Tag>> {
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

        let mut res = HashSet::new();
        for value in indexed_values {
            match value {
                IndexedValue::Data(_) => {
                    res.insert(value.clone());
                }
                IndexedValue::NextTag(next_tag) => {
                    res.extend(Self::walk(graph, next_tag, visited));
                }
            }
        }

        res
    }

    /// Pushes the given modifications to the indexes using the given key.
    ///
    /// Modifications list for each tag, a set of indexed values with the
    /// associated operation to perform on the indexes. Operations can be
    /// additions or deletions.
    ///
    /// *Note*: only one operation per indexed value and per tag can be applied
    /// per push.
    fn push<Tag: Hash + Eq + Clone>(
        &self,
        k: &Key<SEED_LENGTH>,
        items: HashMap<Tag, HashMap<IndexedValue<Tag>, Operation>>,
    ) {
        //let lines = items
        //.into_iter()
        //.map(|(tag, values)| -> Result<_, _> {
        //let lines = self.chain_table.prepare(values.into_iter().map(|v| ))?;
        //Ok((tag, lines))
        //})
        //.collect::<Result<_, _>>();
        todo!()
    }

    /// Searches indexes for the given tags using the given key.
    pub fn search<Tag: Clone + Debug + Hash + Eq + AsRef<[u8]>>(
        &self,
        k: &<EntryTable<ENTRY_TABLE_VALUE_LENGTH, CallbackError, EntryTableDb> as Edx<
            KEY_LENGTH,
            TOKEN_LENGTH,
            ENTRY_TABLE_VALUE_LENGTH,
            Error<CallbackError>,
        >>::Key,
        tags: HashSet<Tag>,
    ) -> Result<HashMap<Tag, HashSet<IndexedValue<Tag>>>, Error<CallbackError>> {
        let graph = HashMap::<Tag, HashSet<IndexedValue<Tag>>>::with_capacity(tags.len());

        // Fetches the graph of indexed values.
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
                let token = et_tokens
                    .get(tag)
                    .ok_or_else(|| Error::Crypto(format!("no token for the given tag: {tag:?}")))?;
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

        let mut res = HashMap::with_capacity(tags.len());
        for tag in tags {
            let values = Self::walk(&graph, &tag, &mut HashSet::new());
            res.insert(tag, values);
        }

        Ok(res)
    }

    /// Adds the given values to the index for the associated tags.
    pub fn add<Tag: Hash + Eq + Clone>(
        &self,
        k: &Key<SEED_LENGTH>,
        items: HashMap<IndexedValue<Tag>, HashSet<Tag>>,
    ) {
        let mut pushed_items = HashMap::<Tag, HashMap<IndexedValue<Tag>, Operation>>::new();
        for (indexed_value, tags) in items {
            for tag in tags {
                pushed_items
                    .entry(tag)
                    .or_default()
                    .insert(indexed_value.clone(), Operation::Addition);
            }
        }
        self.push(k, pushed_items)
    }

    /// Removes the given values from the index for the associated tags.
    pub fn remove<Tag: Hash + Eq + Clone>(
        &self,
        k: &Key<SEED_LENGTH>,
        items: HashMap<IndexedValue<Tag>, HashSet<Tag>>,
    ) {
        let mut pushed_items = HashMap::<Tag, HashMap<IndexedValue<Tag>, Operation>>::new();
        for (indexed_value, tags) in items {
            for tag in tags {
                pushed_items
                    .entry(tag)
                    .or_default()
                    .insert(indexed_value.clone(), Operation::Deletion);
            }
        }
        self.push(k, pushed_items)
    }
}

/// Findex implements an EMM scheme.
///
/// Tokens are the hash of the tag. A reduced size is authorized since this
/// hash only needs collision resistance.
impl<
    const BLOCK_LENGTH: usize,
    const LINE_LENGTH: usize,
    CallbackError: std::error::Error,
    EntryTableDb: entry_table::Callbacks<TOKEN_LENGTH, ENTRY_TABLE_VALUE_LENGTH, CallbackError>,
    ChainTableDb: chain_table::Callbacks<TOKEN_LENGTH, { 2 + BLOCK_LENGTH * LINE_LENGTH }, CallbackError>,
> Emm<KEY_LENGTH, HASH_LENGTH, CallbackError>
    for Findex<BLOCK_LENGTH, LINE_LENGTH, CallbackError, EntryTableDb, ChainTableDb>
where
    [(); 2 + BLOCK_LENGTH * LINE_LENGTH]: Sized,
{
    type Item = IndexedValue<Self::Token>;
    type Key = FindexKey<CallbackError, EntryTableDb>;

    fn derive_keys(&self, seed: &[u8]) -> Self::Key {
        Self::Key {
            token: Key::from_bytes(kdf!(KEY_LENGTH, seed)),
            entry_table: self.entry_table.derive_key(seed),
        }
    }

    fn tokenize(k: &Self::Key, tag: &[u8]) -> Self::Token {
        kmac!(HASH_LENGTH, &k.token, tag)
    }

    fn get(
        &self,
        k: &Self::Key,
        tokens: HashSet<Self::Token>,
    ) -> Result<HashMap<Self::Token, Self::Value>, Error<CallbackError>> {
        let graph = HashMap::<Self::Token, HashSet<Self::Item>>::with_capacity(tokens.len());

        // Fetches the graph of indexed values.
        while !tokens.is_empty() {
            let et_tokens = tokens
                .iter()
                .map(|token| {
                    (
                        *token,
                        self.entry_table.tokenize(&k.entry_table, token.as_ref()),
                    )
                })
                .collect::<HashMap<_, _>>();

            let et_values = self
                .entry_table
                .get(et_tokens.values().cloned().collect())?
                .into_iter()
                .map(|(token, value)| -> Result<_, _> {
                    Ok((token, self.entry_table.resolve(&k.entry_table, value)?))
                })
                .collect::<Result<HashMap<_, _>, Error<CallbackError>>>()?;

            let mut ct_tokens = HashMap::<Self::Token, Vec<_>>::with_capacity(et_values.len());
            let mut ct_keys = HashMap::with_capacity(et_values.len());

            for token in &tokens {
                let et_token = et_tokens.get(token).ok_or_else(|| {
                    Error::Crypto(format!("no token for the given tag: {token:?}"))
                })?;
                if let Some(value) = et_values.get(et_token) {
                    let value = EntryTableValue(value);
                    let k_ct: crate::edx::EdxKey<KEY_LENGTH> =
                        self.chain_table.derive_key(value.seed());

                    ct_tokens.entry(*token).or_default().extend(
                        Self::unroll(0, value.counter() as usize)
                            .map(|ct_tag| self.chain_table.tokenize(&k_ct, &ct_tag.to_be_bytes())),
                    );

                    ct_keys.insert(*token, k_ct);
                }
            }
        }

        let mut res = HashMap::with_capacity(tokens.len());
        for token in tokens {
            let values = Self::walk(&graph, &token, &mut HashSet::new());
            res.insert(token, values);
        }

        Ok(res)
    }

    fn insert(&mut self, k: &Self::Key, values: HashSet<Self::Token, Self::Value>) {
        todo!()
    }
}

impl<
    const BLOCK_LENGTH: usize,
    const LINE_LENGTH: usize,
    CallbackError: std::error::Error,
    EntryTableDb: entry_table::Callbacks<TOKEN_LENGTH, ENTRY_TABLE_VALUE_LENGTH, CallbackError>,
    ChainTableDb: chain_table::Callbacks<TOKEN_LENGTH, { 2 + BLOCK_LENGTH * LINE_LENGTH }, CallbackError>,
    Tag: Hash + PartialEq + Eq,
    Data: Hash + PartialEq + Eq,
> FindexApi<Tag, Data, CallbackError>
    for Findex<BLOCK_LENGTH, LINE_LENGTH, CallbackError, EntryTableDb, ChainTableDb>
where
    [(); 2 + BLOCK_LENGTH * LINE_LENGTH]: Sized,
{
    type Key = <Self as Emm<KEY_LENGTH, HASH_LENGTH, CallbackError>>::Key;
    type Seed = Key<KEY_LENGTH>;

    fn gen_seed(
        &self,
        rng: &mut impl cosmian_crypto_core::reexport::rand_core::CryptoRngCore,
    ) -> Self::Seed {
        todo!()
    }

    fn tokenize(&self, seed: &Self::Seed) -> Self::Key {
        todo!()
    }

    fn search(&self, key: &Self::Key, tags: HashSet<Tag>) -> HashMap<Tag, HashSet<Data>> {
        todo!()
    }

    fn add(
        &mut self,
        key: &Self::Key,
        items: HashMap<Tag, HashSet<Data>>,
    ) -> Result<(), Error<CallbackError>> {
        todo!()
    }

    fn delete(
        &mut self,
        key: &Self::Key,
        items: HashMap<Tag, HashSet<Data>>,
    ) -> Result<(), Error<CallbackError>> {
        todo!()
    }
}
