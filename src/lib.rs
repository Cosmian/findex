//! Findex is a cryptographic algorithm allowing to securely maintain an
//! encrypted index.
//!
//! It uses a generic Dictionary Encryption Scheme (Dx-Enc) as building block to
//! implement a MultiMap Encryption Scheme (MM-Enc). A Graph Encryption Scheme
//! (Gx-Enc) is then built on top of the MM-Enc scheme and finally an `Index`
//! trait built on top of this Gx-Enc scheme allows indexing both `Location`s
//! and `Keyword`s.
//!
//! The `Index` traits is not a cryptographic algorithm, It is used to simplify
//! the interface and to hide the cryptographic details of the implementation
//! when it is possible.

// Macro declarations should come first.
#[macro_use]
pub mod macros;

mod edx;
mod error;
mod findex_graph;
mod findex_mm;
mod index;
mod parameters;

#[cfg(any(test, feature = "in_memory"))]
pub use edx::in_memory::{InMemoryEdx, KvStoreError};
pub use edx::{chain_table::ChainTable, entry_table::EntryTable, DxEnc, EdxStore, EncryptedValue};
pub use error::{CallbackErrorTrait, CoreError, Error};
pub use findex_graph::IndexedValue;
pub use findex_mm::{ENTRY_LENGTH, LINK_LENGTH};
pub use index::{Findex, Index, Keyword, Label, Location, UserKey};
pub use parameters::*;

#[cfg(test)]
mod example {
    use std::collections::{HashMap, HashSet};

    use crate::{
        ChainTable, DxEnc, EntryTable, Findex, InMemoryEdx, Index, IndexedValue, Keyword, Label,
        Location,
    };

    async fn user_interrupt(
        _res: HashMap<Keyword, HashSet<IndexedValue<Keyword, Location>>>,
    ) -> Result<bool, String> {
        Ok(false)
    }

    #[actix_rt::test]
    async fn index_and_search() {
        // Values to index.
        let kwd1 = Keyword::from("Keyword 1");
        let kwd2 = Keyword::from("Keyword 2");

        let loc1 = Location::from("Location 1");
        let loc2 = Location::from("Location 2");

        // Let's create a new index using the in-memory EDX provided in the tests.
        let index = Findex::new(
            EntryTable::setup(InMemoryEdx::default()),
            ChainTable::setup(InMemoryEdx::default()),
        );

        // Let's create a new key for our index.
        let key = index.keygen();

        // Findex uses a public label with the private key. Let's generate a new label.
        let label = Label::from("My public label");

        // Let's index `loc1` for `kwd1`, `loc2` for `kwd2` and `kwd2` for `kwd1`.
        index
            .add(
                &key,
                &label,
                HashMap::from_iter([
                    (
                        IndexedValue::Data(loc1.clone()),
                        HashSet::from_iter([kwd1.clone()]),
                    ),
                    (
                        IndexedValue::Data(loc2.clone()),
                        HashSet::from_iter([kwd2.clone()]),
                    ),
                    (
                        IndexedValue::Pointer(kwd2.clone()),
                        HashSet::from_iter([kwd1.clone()]),
                    ),
                ]),
            )
            .await
            .expect("Error while indexing additions.");

        let res = index
            .search(
                &key,
                &label,
                HashSet::from_iter([kwd1.clone()]),
                &user_interrupt,
            )
            .await
            .expect("Error while searching.");

        // Since `kw2` was indexed for `kwd1`, searching for `kwd1` also retrieves
        // `loc2`.
        assert_eq!(
            res,
            HashMap::from_iter([(kwd1.clone(), HashSet::from_iter([loc1.clone(), loc2]))])
        );

        // Let's delete the indexation of `kwd2` for `kwd1`.
        index
            .delete(
                &key,
                &label,
                HashMap::from_iter([(
                    IndexedValue::Pointer(kwd2),
                    HashSet::from_iter([kwd1.clone()]),
                )]),
            )
            .await
            .expect("Error while indexing deletions.");

        let res = index
            .search(
                &key,
                &label,
                HashSet::from_iter([kwd1.clone()]),
                &user_interrupt,
            )
            .await
            .expect("Error while searching.");

        // Since the indexation of `kw2` for `kwd1` was deleted, searching for `kwd1` no
        // longer retrieves `loc2`.
        assert_eq!(
            res,
            HashMap::from_iter([(kwd1, HashSet::from_iter([loc1]))])
        );
    }
}
