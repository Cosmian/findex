//! Findex is a cryptographic algorithm allowing to securely maintain an encrypted index.
//!
//! It uses a generic Dictionary Encryption Scheme (Dx-Enc) as building block to implement a
//! Multi-Map Encryption Scheme (MM-Enc). A Graph Encryption Scheme (Gx-Enc) is then built on top
//! of the MM-Enc scheme and finally an `Index` trait built on top of this Gx-Enc scheme allows
//! indexing both `Data` and `Keyword`s.
//!
//! The `Index` traits is not a cryptographic one. It is used to simplify the interface and to hide
//! the details of the cryptographic implementation when it is possible.

#![allow(async_fn_in_trait)]

// Macro declarations should come first.
#[macro_use]
pub mod macros;

mod db;
mod error;
mod findex;
mod index;
mod traits;
mod vera;

#[cfg(feature = "in_memory")]
pub use db::in_memory_db::{InMemoryDb, InMemoryDbError};
pub use db::{Edx, EdxDbInterface, Token};
pub use error::{CoreError, DbInterfaceErrorTrait, Error};
pub use findex::{Error as FindexError, Findex, Link, Metadata};
pub use index::{Index, IndexError, UserKey};
pub use traits::*;
pub use vera::{Error as VeraError, Tag, Vera};

/// Minimal seed length preserving 128 bits of post-quantum security.
pub const MIN_SEED_LENGTH: usize = 32;

impl_byte_vector!(Keyword, "Keyword");
impl_byte_vector!(Data, "Data");

#[cfg(test)]
mod example {
    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};

    use crate::*;

    #[actix_rt::test]
    async fn index_and_search() {
        /*
         * Findex instantiation.
         */
        let mut rng = CsRng::from_entropy();
        // Let's create a new key for our index.
        let key = UserKey::random(&mut rng);

        // Let's create two connection to store the Entry and Chain tables.
        let entry_table = InMemoryDb::default();
        let chain_table = InMemoryDb::default();

        // Let's create a new index using the provided Entry and Chain table implementation and the
        // in-memory EDX implementation provided for test purpose.
        let index = Index::new(&key, entry_table.clone(), chain_table.clone()).unwrap();

        ////////////////////////////////////////////////////////////////////////////////
        //                                                                            //
        //  Let's associate `loc1` to `kwd1`, `loc2` to `kwd2` and `kwd1`.            //
        //  The future state of the index can be represented as a JSON:               //
        //                                                                            //
        //  ```json                                                                   //
        //  {                                                                         //
        //      'kwd1' : ['loc1', 'loc2'],                                            //
        //      'kwd2' : ['loc2'],                                                    //
        //  }                                                                         //
        //  ```                                                                       //
        //                                                                            //
        ////////////////////////////////////////////////////////////////////////////////

        let kwd1 = Keyword::from("Keyword 1");
        let kwd2 = Keyword::from("Keyword 2");
        let loc1 = Keyword::from("Location 1");
        let loc2 = Keyword::from("Location 2");

        let inserted_index = mm! {
            (kwd1.clone(), vec![loc1.clone(), loc2.clone()]),
            (kwd2.clone(), vec![loc2.clone()]),
        };

        index
            .add(inserted_index.clone())
            .await
            .expect("Error while indexing additions.");

        let res = index
            .search(set! {kwd1.clone()})
            .await
            .expect("Error while searching.");

        assert_eq!(res, mm! {(kwd1.clone(), vec![loc1.clone(), loc2.clone()])});

        ////////////////////////////////////////////////////////////////////////////////
        //                                                                            //
        //  Let's delete the association `kwd1`->`loc2`. This actually associates the //
        //  negation of `loc2` to `kwd1`.                                             //
        //                                                                            //
        //  ```json                                                                   //
        //  {                                                                         //
        //      'kwd1' : ['loc1', 'loc2', !'loc2'],                                   //
        //      'kwd2' : ['loc2'],                                                    //
        //  }                                                                         //
        //  ```                                                                       //
        //                                                                            //
        ////////////////////////////////////////////////////////////////////////////////

        index
            .delete(mm! {(kwd1.clone(), vec![loc2.clone()])})
            .await
            .expect("Error while indexing deletions.");

        let res = index
            .search(Set::from_iter([kwd1.clone()]))
            .await
            .expect("Error while searching.");

        // Searching for `kwd1` no longer retrieves `loc2`.
        assert_eq!(res, mm!((kwd1.clone(), vec![loc1.clone()])));

        ////////////////////////////////////////////////////////////////////////////////
        //                                                                            //
        //  Let's compact the index in order to collapse the negation.                //
        //                                                                            //
        //  ```json                                                                   //
        //  {                                                                         //
        //      'kwd1' : ['loc1'],                                                    //
        //      'kwd2' : ['loc2'],                                                    //
        //  }                                                                         //
        //  ```                                                                       //
        //                                                                            //
        ////////////////////////////////////////////////////////////////////////////////

        // Before compacting, the Entry Table holds 2 lines since two keywords were indexed.
        assert_eq!(2, entry_table.len());

        // Before compacting, the Entry Table holds 3 lines since four associations were indexed
        // but two of them were indexed for the same keyword in the same `add` operations and the
        // indexed values are small enough to hold in the same line.
        assert_eq!(3, chain_table.len());

        index.compact().await.unwrap();

        // After compacting, the Entry Table still holds 2 lines since each indexed keyword still
        // holds at least one association.
        assert_eq!(2, entry_table.len());

        // After compacting, the Chain Table holds 2 lines since the two associations
        // `kwd1`->`kwd2` and `kwd1`->!`kwd2` collapsed.
        assert_eq!(2, chain_table.len());

        ////////////////////////////////////////////////////////////////////////////////
        //                                                                            //
        //  Let's delete the association `kwd2`->`loc2` and compact the index in      //
        //  order to collapse the negation. Since `kwd2` indexes no more keyword,     //
        //  it should be removed from the index:                                      //
        //                                                                            //
        //  ```json                                                                   //
        //  {                                                                         //
        //      'kwd1' : ['loc1'],                                                    //
        //  }                                                                         //
        //  ```                                                                       //
        //                                                                            //
        ////////////////////////////////////////////////////////////////////////////////

        index
            .delete(mm!((kwd2, vec![loc2.clone()])))
            .await
            .expect("Error while indexing deletions.");

        // The Entry Table still holds 2 lines since no more keywords were
        // indexed and the deletion is an insertion.
        assert_eq!(2, entry_table.len());

        // The Chain Table holds 3 lines since a new association was indexed.
        assert_eq!(3, chain_table.len());

        index.compact().await.unwrap();

        // The Entry Table now holds only 1 line: since `kwd2` does not index
        // any value anymore, it was removed from the index.
        // assert_eq!(1, entry_table.len());

        // The Chain Table holds 1 lines since a two associations collapsed.
        assert_eq!(1, chain_table.len());
    }
}
