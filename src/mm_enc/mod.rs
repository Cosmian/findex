use std::fmt::Display;

use async_trait::async_trait;

use crate::{dx_enc::TagSet, CoreError, DbInterface};

mod findex;
mod structs;

pub use findex::Findex;
pub use structs::{Mm, ENTRY_LENGTH, LINK_LENGTH};

#[derive(Debug)]
pub enum Error<EntryError: std::error::Error, ChainError: std::error::Error> {
    Core(CoreError),
    Entry(EntryError),
    Chain(ChainError),
}

impl<EntryError: std::error::Error, ChainError: std::error::Error> From<CoreError>
    for Error<EntryError, ChainError>
{
    fn from(e: CoreError) -> Self {
        Self::Core(e)
    }
}

impl<EntryError: std::error::Error, ChainError: std::error::Error> Display
    for Error<EntryError, ChainError>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Entry(e) => write!(f, "Entry DX-Enc error: {e}"),
            Error::Chain(e) => write!(f, "Chain DX-Enc error: {e}"),
            Error::Core(e) => write!(f, "{e}"),
        }
    }
}

impl<EntryError: std::error::Error, ChainError: std::error::Error> std::error::Error
    for Error<EntryError, ChainError>
{
}

#[async_trait(?Send)]
pub trait CsRhMmEnc: Sized {
    type DbConnection: DbInterface + Clone;
    type Error: std::error::Error;
    type Item;

    /// Creates a new instance of the scheme.
    ///
    /// Deterministically generates keys using the given seed and use the given
    /// database connection to store the EMM.
    fn setup(seed: &[u8], connection: Self::DbConnection) -> Result<Self, Self::Error>;

    /// Returns a restriction of the stored MM to the given tags.
    async fn search(&self, tags: TagSet) -> Result<Mm<Self::Item>, Self::Error>;

    /// Extends the stored MM with the given one.
    async fn insert(&self, mm: Mm<Self::Item>) -> Result<(), Self::Error>;

    /// Extracts the given MM out of the stored one.
    async fn delete(&self, mm: Mm<Self::Item>) -> Result<(), Self::Error>;

    /// Compacts the stored EMM.
    async fn compact(&self) -> Result<(), Self::Error>;

    /// Rebuilds the stored EMM using the given seed.
    async fn rebuild(self, seed: &[u8]) -> Result<Self, Self::Error>;
}

// #[cfg(test)]
// mod tests {
//     use std::{
//         collections::HashMap,
//         sync::{Arc, Mutex},
//     };

//     use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};

//     use crate::{
//         edx::{chain_table::ChainTable, entry_table::EntryTable, in_memory::InMemoryDb},
//         findex_mm::{FindexMultiMap, MmEnc, Operation},
//         CsRhDxEnc, Label,
//     };

//     #[actix_rt::test]
//     async fn test_insert_get() {
//         let rng = Arc::new(Mutex::new(CsRng::from_entropy()));
//         let label = Label::random(&mut *rng.lock().expect(""));

//         let entry_table = EntryTable::setup(InMemoryDb::default());
//         let chain_table = ChainTable::setup(InMemoryDb::default());
//         let findex = FindexMultiMap::new(entry_table, chain_table);

//         // Generates 10 chains of 32 bytes values.
//         let n = 10;
//         let mut chains = HashMap::with_capacity(n);
//         for i in 0..n {
//             let tag = format!("Tag {i}").as_bytes().to_vec();
//             let values = (0..n)
//                 .map(|j| {
//                     (
//                         Operation::Addition,
//                         format!("Value ({i},{j})").as_bytes().to_vec(),
//                     )
//                 })
//                 .collect();
//             chains.insert(tag, values);
//         }

//         let findex_seed = findex.gen_seed(&mut *rng.lock().expect("could not lock mutex"));
//         let findex_key = findex.derive_keys(&findex_seed);
//         findex
//             .insert(rng, &findex_key, chains.clone(), &label)
//             .await
//             .unwrap();

//         let res = findex
//             .get(&findex_key, chains.keys().cloned().collect(), &label)
//             .await
//             .unwrap();

//         for (tag, chain) in chains {
//             let res = res.get(&tag).unwrap();

//             assert_eq!(chain.len(), res.len());

//             for (op, value) in chain {
//                 if Operation::Addition == op {
//                     assert!(res.contains(&value));
//                 }
//             }
//         }
//     }
// }
