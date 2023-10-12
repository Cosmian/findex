//! Findex Multi-Map Encryption scheme (MM-Enc).
//!
//! The Findex MM encryption scheme is in charge of storing variable-length
//! chains of variable-length values into a dictionary storing constant length
//! values.
//!
//! Tho this aim, it uses an auxiliary EDX called Entry Table in order to store
//! chain metadata:
//! - a seed used to derive the chain keys
//! - a hash used to derive the EDX token for this value
//! - the last token of the chain
//!
//! The EDX used to store the chains is called Chain Table. Each chain component
//! is called a link. A chain is therefore a sequence of links. The key used to
//! encrypt a given chain is derived from the seed stored in its associated
//! entry. The Chain Table tokens are derived from each other using dedicated
//! key derived from the same entry seed. The first token is derived from the
//! hash stored in the metadata.
//!
//! The last chain token stored in the Entry Table along with conditional (cf
//! [`DxEnc::upsert()`](crate::DxEnc::upsert)), atomic modifications of this
//! table allow avoiding races between concurrent additions to the same chain.

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;
use zeroize::ZeroizeOnDrop;

use crate::{edx::DxEnc, CallbackErrorTrait, Error, Label};

mod compact;
mod mm;
mod structs;

pub use structs::{CompactingData, Operation, ENTRY_LENGTH, LINK_LENGTH};

#[async_trait(?Send)]
pub trait MmEnc<const SEED_LENGTH: usize, EdxError: CallbackErrorTrait> {
    /// Seed used to derive the key.
    type Seed: Sized + ZeroizeOnDrop + AsRef<[u8]> + Default + AsMut<[u8]>;

    /// Cryptographic key.
    type Key: Sized + ZeroizeOnDrop;

    /// Type of the values stored inside the multi-map.
    type Item;

    /// Error returned by the multi-map encryption scheme.
    type Error: std::error::Error;

    /// Generates a new random seed.
    fn gen_seed(&self, rng: &mut impl CryptoRngCore) -> Self::Seed;

    /// Deterministically derives a key from the given seed.
    fn derive_keys(&self, seed: &Self::Seed) -> Self::Key;

    /// Queries the encrypted multi-map for the given tags and returns the
    /// decrypted values.
    async fn get<Tag: Debug + Hash + Eq + AsRef<[u8]>>(
        &self,
        key: &Self::Key,
        tags: HashSet<Tag>,
        label: &Label,
    ) -> Result<HashMap<Tag, HashSet<Self::Item>>, Self::Error>;

    /// Applies the given modifications to the encrypted multi-map. Returns the
    /// set of Tags added to the Multi-Map.
    async fn insert<Tag: Hash + Eq + AsRef<[u8]>>(
        &self,
        rng: Arc<Mutex<impl CryptoRngCore>>,
        key: &Self::Key,
        modifications: HashMap<Tag, Vec<(Operation, Self::Item)>>,
        label: &Label,
    ) -> Result<HashSet<Tag>, Self::Error>;
}

#[derive(Debug)]
pub struct FindexMultiMap<
    UserError: CallbackErrorTrait,
    EntryTable: DxEnc<ENTRY_LENGTH, Error = Error<UserError>>,
    ChainTable: DxEnc<LINK_LENGTH, Error = Error<UserError>>,
> {
    pub entry_table: EntryTable,
    pub chain_table: ChainTable,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};

    use crate::{
        edx::{chain_table::ChainTable, entry_table::EntryTable, in_memory::InMemoryEdx},
        findex_mm::{FindexMultiMap, MmEnc, Operation},
        DxEnc, Label,
    };

    #[actix_rt::test]
    async fn test_insert_get() {
        let rng = Arc::new(Mutex::new(CsRng::from_entropy()));
        let label = Label::random(&mut *rng.lock().expect(""));

        let entry_table = EntryTable::setup(InMemoryEdx::default());
        let chain_table = ChainTable::setup(InMemoryEdx::default());
        let findex = FindexMultiMap::new(entry_table, chain_table);

        // Generates 10 chains of 32 bytes values.
        let n = 10;
        let mut chains = HashMap::with_capacity(n);
        for i in 0..n {
            let tag = format!("Tag {i}").as_bytes().to_vec();
            let values = (0..n)
                .map(|j| {
                    (
                        Operation::Addition,
                        format!("Value ({i},{j})").as_bytes().to_vec(),
                    )
                })
                .collect();
            chains.insert(tag, values);
        }

        let findex_seed = findex.gen_seed(&mut *rng.lock().expect("could not lock mutex"));
        let findex_key = findex.derive_keys(&findex_seed);
        findex
            .insert(rng, &findex_key, chains.clone(), &label)
            .await
            .unwrap();

        let res = findex
            .get(&findex_key, chains.keys().cloned().collect(), &label)
            .await
            .unwrap();

        for (tag, chain) in chains {
            let res = res.get(&tag).unwrap();

            assert_eq!(chain.len(), res.len());

            for (op, value) in chain {
                if Operation::Addition == op {
                    assert!(res.contains(&value))
                }
            }
        }
    }
}
