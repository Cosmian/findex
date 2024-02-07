use std::fmt::Debug;

use async_trait::async_trait;

use crate::{
    dx_enc::{CsRhDxEnc, TagSet},
    DbInterface, DbInterfaceErrorTrait, Error,
};

mod findex;
mod structs;

pub use structs::{ENTRY_LENGTH, LINK_LENGTH};

use self::structs::Mm;

#[async_trait(?Send)]
pub trait MmEnc {
    /// Error returned by the multi-map encryption scheme.
    type Error: std::error::Error;

    /// Creates a new instance of the scheme.
    ///
    /// Deterministically generates keys using the given seed and use the given
    /// database connection to store the EMM.
    fn setup(seed: &[u8], connection: impl DbInterface) -> Result<Self, Self::Error>;

    /// Returns a restriction of the stored MM to the given tags.
    async fn get(&self, tags: TagSet) -> Result<Mm, Self::Error>;

    /// Extends the stored MM with the given one.
    async fn insert(&self, mm: Mm) -> Result<(), Self::Error>;

    /// Extracts the given MM out of the stored one.
    async fn delete(&self, mm: Mm) -> Result<(), Self::Error>;

    /// Compacts the stored EMM.
    async fn compact(&self) -> Result<(), Self::Error>;

    /// Rebuilds the stored EMM using the given seed.
    async fn rebuild(self, seed: &[u8]) -> Result<Self, Self::Error>;
}

#[derive(Debug)]
pub struct FindexMultiMap<
    UserError: DbInterfaceErrorTrait,
    EntryTable: CsRhDxEnc<ENTRY_LENGTH, Error = Error<UserError>>,
    ChainTable: CsRhDxEnc<LINK_LENGTH, Error = Error<UserError>>,
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
        edx::{chain_table::ChainTable, entry_table::EntryTable, in_memory::InMemoryDb},
        findex_mm::{FindexMultiMap, MmEnc, Operation},
        CsRhDxEnc, Label,
    };

    #[actix_rt::test]
    async fn test_insert_get() {
        let rng = Arc::new(Mutex::new(CsRng::from_entropy()));
        let label = Label::random(&mut *rng.lock().expect(""));

        let entry_table = EntryTable::setup(InMemoryDb::default());
        let chain_table = ChainTable::setup(InMemoryDb::default());
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
                    assert!(res.contains(&value));
                }
            }
        }
    }
}
