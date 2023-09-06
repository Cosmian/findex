//! Findex Graph Encryption Scheme (GX-Enc).
//!
//! Uses the Findex MM-Enc scheme in order to sec0ly store a graph. This graph
//! stores `IndexedValue`s for `Tag`s. An `IndexedValue` can be ei0r a
//! `Pointer` to another `Tag` or a `Data` containing a `Value`.

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    future::Future,
    hash::Hash,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;
use zeroize::ZeroizeOnDrop;

use crate::{
    findex_mm::{FindexMultiMap, Operation, ENTRY_LENGTH, LINK_LENGTH},
    CallbackErrorTrait, DxEnc, Error, Label,
};

mod compact;
mod graph;
mod structs;

pub use structs::IndexedValue;

#[async_trait]
pub trait GxEnc<EdxError: CallbackErrorTrait>: Sync + Send {
    /// Seed used to derive the key.
    type Seed: Sized + ZeroizeOnDrop + AsRef<[u8]> + Default + AsMut<[u8]> + Sync + Send;

    /// Cryptographic key.
    type Key: Sized + ZeroizeOnDrop + Sync + Send;

    /// Error type returned by the GxEnc scheme.
    type Error: std::error::Error + Sync + Send;

    /// Generates a new random seed.
    fn gen_seed(&self, rng: &mut impl CryptoRngCore) -> Self::Seed;

    /// Deterministically derives a key from the given seed.
    fn derive_keys(&self, seed: &Self::Seed) -> Self::Key;

    /// Queries the encrypted graph for the given tags and returns the
    /// decrypted values.
    async fn get<
        Tag: Debug + Send + Sync + Hash + Eq + Clone + AsRef<[u8]> + From<Vec<u8>>,
        Value: Hash + Send + Sync + Eq + Clone + From<Vec<u8>>,
        F: Send + Sync + Future<Output = bool>,
        Interrupt: Send + Sync + Fn(HashMap<Tag, HashSet<IndexedValue<Tag, Value>>>) -> F,
    >(
        &self,
        key: &Self::Key,
        tags: HashSet<Tag>,
        label: &Label,
        interrupt: &Interrupt,
    ) -> Result<HashMap<Tag, HashSet<IndexedValue<Tag, Value>>>, Self::Error>;

    /// Encrypts and inserts the given items into the graph. Returns the set of
    /// tags added to the index.
    #[allow(clippy::type_complexity)]
    async fn insert<Tag: Send + Sync + Hash + Eq + AsRef<[u8]>, Value: Send + Sync + AsRef<[u8]>>(
        &mut self,
        rng: Arc<Mutex<impl Send + Sync + CryptoRngCore>>,
        key: &Self::Key,
        items: HashMap<Tag, Vec<(Operation, IndexedValue<Tag, Value>)>>,
        label: &Label,
    ) -> Result<HashSet<Tag>, Self::Error>;
}

#[derive(Debug)]
pub struct FindexGraph<
    UserError: CallbackErrorTrait,
    EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>>,
    ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
> {
    pub findex_mm: FindexMultiMap<UserError, EntryTable, ChainTable>,
}

impl<
        UserError: CallbackErrorTrait,
        EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>>,
        ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
    > FindexGraph<UserError, EntryTable, ChainTable>
{
    pub fn new(entry_table: EntryTable, chain_table: ChainTable) -> Self {
        Self {
            findex_mm: FindexMultiMap {
                entry_table,
                chain_table,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        fmt::Debug,
        hash::Hash,
        sync::{Arc, Mutex},
    };

    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};

    use crate::{
        edx::in_memory::InMemoryEdx,
        findex_graph::{FindexGraph, GxEnc, IndexedValue},
        findex_mm::Operation,
        ChainTable, DxEnc, EntryTable, Label,
    };

    async fn user_interrupt<
        Tag: Debug + Hash + Eq + Clone + AsRef<[u8]> + From<Vec<u8>>,
        Value: Hash + Eq + Clone + From<Vec<u8>>,
    >(
        _res: HashMap<Tag, HashSet<IndexedValue<Tag, Value>>>,
    ) -> bool {
        false
    }

    #[actix_rt::test]
    async fn test_insert_get() {
        let rng = Arc::new(Mutex::new(CsRng::from_entropy()));
        let label = Label::random(&mut *rng.lock().expect(""));

        let entry_table = EntryTable::setup(InMemoryEdx::default());
        let chain_table = ChainTable::setup(InMemoryEdx::default());
        let mut findex = FindexGraph::new(entry_table, chain_table);

        let findex_seed = findex.gen_seed(&mut *rng.lock().expect("could not lock mutex"));
        let findex_key = findex.derive_keys(&findex_seed);

        // Build the following cyclic index:
        //
        // a -> b -> c -> d -> h
        //      ^         |
        //      |         v
        // i -> g <- f <- e
        //
        // The results should be:
        //
        // {
        //      a: {L_b, L_c, L_d, L_h, L_e, L_f, L_g},
        //      i: {L_g, L_b, L_c, L_d, L_h, L_e, L_f}
        //  }
        //
        let tag_a = b"tag a".to_vec();
        let tag_b = b"tag b".to_vec();
        let tag_c = b"tag c".to_vec();
        let tag_d = b"tag d".to_vec();
        let tag_e = b"tag e".to_vec();
        let tag_f = b"tag f".to_vec();
        let tag_g = b"tag g".to_vec();
        let tag_h = b"tag h".to_vec();
        let tag_i = b"tag i".to_vec();

        let loc_a = b"location a".to_vec();
        let loc_b = b"location b".to_vec();
        let loc_c = b"location c".to_vec();
        let loc_d = b"location d".to_vec();
        let loc_e = b"location e".to_vec();
        let loc_f = b"location f".to_vec();
        let loc_g = b"location g".to_vec();
        let loc_h = b"location h".to_vec();
        let loc_i = b"location i".to_vec();

        let mut cyclic_graph = HashMap::new();

        cyclic_graph.insert(
            tag_a.clone(),
            vec![
                (Operation::Addition, IndexedValue::Data(loc_a.clone())),
                (Operation::Addition, IndexedValue::Pointer(tag_b.clone())),
            ],
        );
        cyclic_graph.insert(
            tag_b.clone(),
            vec![
                (Operation::Addition, IndexedValue::Data(loc_b.clone())),
                (Operation::Addition, IndexedValue::Pointer(tag_c.clone())),
            ],
        );
        cyclic_graph.insert(
            tag_c.clone(),
            vec![
                (Operation::Addition, IndexedValue::Data(loc_c.clone())),
                (Operation::Addition, IndexedValue::Pointer(tag_d.clone())),
            ],
        );
        cyclic_graph.insert(
            tag_d.clone(),
            vec![
                (Operation::Addition, IndexedValue::Data(loc_d.clone())),
                (Operation::Addition, IndexedValue::Pointer(tag_h.clone())),
                (Operation::Addition, IndexedValue::Pointer(tag_e.clone())),
            ],
        );
        cyclic_graph.insert(
            tag_e.clone(),
            vec![
                (Operation::Addition, IndexedValue::Data(loc_e.clone())),
                (Operation::Addition, IndexedValue::Pointer(tag_f.clone())),
            ],
        );
        cyclic_graph.insert(
            tag_f.clone(),
            vec![
                (Operation::Addition, IndexedValue::Data(loc_f.clone())),
                (Operation::Addition, IndexedValue::Pointer(tag_g.clone())),
            ],
        );
        cyclic_graph.insert(
            tag_g.clone(),
            vec![
                (Operation::Addition, IndexedValue::Data(loc_g.clone())),
                (Operation::Addition, IndexedValue::Pointer(tag_a.clone())),
            ],
        );
        cyclic_graph.insert(
            tag_h.clone(),
            vec![(Operation::Addition, IndexedValue::Data(loc_h.clone()))],
        );
        cyclic_graph.insert(
            tag_i.clone(),
            vec![
                (Operation::Addition, IndexedValue::Data(loc_i.clone())),
                (Operation::Addition, IndexedValue::Pointer(tag_g.clone())),
            ],
        );

        // Upsert the graph.
        findex
            .insert(rng, &findex_key, cyclic_graph, &label)
            .await
            .unwrap();

        let res = findex
            .get(
                &findex_key,
                HashSet::from_iter([tag_a.clone(), tag_i.clone()]),
                &label,
                &user_interrupt,
            )
            .await
            .unwrap();

        assert!(res.contains_key(&tag_a));
        assert!(res.contains_key(&tag_b));
        assert!(res.contains_key(&tag_c));
        assert!(res.contains_key(&tag_d));
        assert!(res.contains_key(&tag_e));
        assert!(res.contains_key(&tag_f));
        assert!(res.contains_key(&tag_g));
        assert!(res.contains_key(&tag_h));
        assert!(res.contains_key(&tag_i));

        let res_a: HashSet<Vec<u8>> = findex.walk(&res, &tag_a, &mut HashSet::new());

        assert!(res_a.contains(&loc_a));
        assert!(res_a.contains(&loc_b));
        assert!(res_a.contains(&loc_c));
        assert!(res_a.contains(&loc_d));
        assert!(res_a.contains(&loc_e));
        assert!(res_a.contains(&loc_f));
        assert!(res_a.contains(&loc_g));
        assert!(res_a.contains(&loc_h));

        let res_i = findex.walk(&res, &tag_i, &mut HashSet::new());

        assert!(res_i.contains(&loc_i));
        assert!(res_i.contains(&loc_b));
        assert!(res_i.contains(&loc_c));
        assert!(res_i.contains(&loc_d));
        assert!(res_i.contains(&loc_e));
        assert!(res_i.contains(&loc_f));
        assert!(res_i.contains(&loc_g));
        assert!(res_i.contains(&loc_h));

        println!(
            "ET length ({} lines), size ({}B)",
            findex.findex_mm.entry_table.0.len(),
            findex.findex_mm.entry_table.0.size()
        );

        println!(
            "CT length ({} lines), size ({}B)",
            findex.findex_mm.chain_table.0.len(),
            findex.findex_mm.chain_table.0.size()
        );
    }
}
