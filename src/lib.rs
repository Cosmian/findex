//! Findex is a cryptographic algorithm allowing to securely maintain an encrypted index.
//!
//! It uses a generic Dictionary Encryption Scheme (Dx-Enc) as building block to implement a
//! Multi-Map Encryption Scheme (MM-Enc). A Graph Encryption Scheme (Gx-Enc) is then built on top
//! of the MM-Enc scheme and finally an `Index` trait built on top of this Gx-Enc scheme allows
//! indexing both `Data` and `Keyword`s.
//!
//! The `Index` traits is not a cryptographic one. It is used to simplify the interface and to hide
//! the details of the cryptographic implementation when it is possible.

// Macro declarations should come first.
#[macro_use]
pub mod macros;

mod db;
mod dx_enc;
mod error;
// mod gx_enc;
// mod index;
mod mm_enc;
mod parameters;

#[cfg(any(test, feature = "in_memory"))]
pub use db::tests::{InMemoryDb, InMemoryDbError};
pub use db::DbInterface;
pub use dx_enc::{CsRhDxEnc, DynRhDxEnc, Vera};
pub use error::{CoreError, DbInterfaceErrorTrait, Error};

// pub use mm_enc::{CsRhMmEnc, Findex};
// pub use index::{
//     Data, Findex, Index, IndexedValueToKeywordsMap, Keyword, KeywordToDataMap, Keywords, Label,
//     UserKey,
// };
pub use parameters::*;

// #[cfg(test)]
// mod example {
//     use std::collections::HashSet;

//     use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng, RandomFixedSizeCBytes};

//     use crate::{
//         ChainTable, CsRhDxEnc, Data, EntryTable, Findex, InMemoryDb, Index, IndexedValue,
//         IndexedValueToKeywordsMap, Keyword, KeywordToDataMap, Keywords, Label, UserKey,
//     };

//     #[actix_rt::test]
//     async fn index_and_search() {
//         /*
//          * Findex instantiation.
//          */
//         let mut rng = CsRng::from_entropy();
//         // Let's create a new key for our index.
//         let key = UserKey::new(&mut rng);
//         // Findex uses a public label with the private key. Let's generate a new label.
//         let label = Label::from("My public label");

//         // Let's create a new index using the provided Entry and Chain table implementation and the
//         // in-memory EDX implementation provided for test purpose.
//         let index = Findex::new(
//             EntryTable::setup(InMemoryDb::default()),
//             ChainTable::setup(InMemoryDb::default()),
//         );

//         ////////////////////////////////////////////////////////////////////////////////
//         //                                                                            //
//         //  Let's associate `loc1` to `kwd1`, `loc2` to `kwd2` and `kwd2` to `kwd1`.  //
//         //  The future state of the index can be represented as a JSON:               //
//         //                                                                            //
//         //  ```json                                                                   //
//         //  {                                                                         //
//         //      'kwd1' : ['loc1', 'kwd2'],                                            //
//         //      'kwd2' : ['loc2'],                                                    //
//         //  }                                                                         //
//         //  ```                                                                       //
//         //                                                                            //
//         ////////////////////////////////////////////////////////////////////////////////

//         let kwd1 = Keyword::from("Keyword 1");
//         let kwd2 = Keyword::from("Keyword 2");
//         let loc1 = Data::from("Location 1");
//         let loc2 = Data::from("Location 2");

//         let res = index
//             .add(
//                 &key,
//                 &label,
//                 IndexedValueToKeywordsMap::from_iter([
//                     (
//                         IndexedValue::Data(loc1.clone()),
//                         HashSet::from_iter([kwd1.clone()]),
//                     ),
//                     (
//                         IndexedValue::Data(loc2.clone()),
//                         HashSet::from_iter([kwd2.clone()]),
//                     ),
//                     (
//                         IndexedValue::Pointer(kwd2.clone()),
//                         HashSet::from_iter([kwd1.clone()]),
//                     ),
//                 ]),
//             )
//             .await
//             .expect("Error while indexing additions.");

//         // Two new keywords were added to the index.
//         assert_eq!(2, res.len());

//         let res = index
//             .search(
//                 &key,
//                 &label,
//                 Keywords::from_iter([kwd1.clone()]),
//                 &|_| async { Ok(false) },
//             )
//             .await
//             .expect("Error while searching.");

//         // Searching for `kwd1` also retrieves `loc2` since `kwd2` is associated to `kwd1` and that
//         // Findex search is recursive.
//         assert_eq!(
//             res,
//             KeywordToDataMap::from_iter([(
//                 kwd1.clone(),
//                 HashSet::from_iter([loc1.clone(), loc2.clone()])
//             )])
//         );

//         ////////////////////////////////////////////////////////////////////////////////
//         //                                                                            //
//         //  Let's delete the association `kwd1`->`kwd2`. This actually associates the //
//         //  negation of `kwd2` to `kwd1`.                                             //
//         //                                                                            //
//         //  ```json                                                                   //
//         //  {                                                                         //
//         //      'kwd1' : ['loc1', 'kwd2', !'kwd2'],                                   //
//         //      'kwd2' : ['loc2'],                                                    //
//         //  }                                                                         //
//         //  ```                                                                       //
//         //                                                                            //
//         ////////////////////////////////////////////////////////////////////////////////

//         let res = index
//             .delete(
//                 &key,
//                 &label,
//                 IndexedValueToKeywordsMap::from_iter([(
//                     IndexedValue::Pointer(kwd2.clone()),
//                     HashSet::from_iter([kwd1.clone()]),
//                 )]),
//             )
//             .await
//             .expect("Error while indexing deletions.");

//         // No new keyword were added to the index.
//         assert_eq!(0, res.len());

//         let res = index
//             .search(
//                 &key,
//                 &label,
//                 Keywords::from_iter([kwd1.clone()]),
//                 &|_| async { Ok(false) },
//             )
//             .await
//             .expect("Error while searching.");

//         // Searching for `kwd1` no longer retrieves `loc2`.
//         assert_eq!(
//             res,
//             KeywordToDataMap::from_iter([(kwd1, HashSet::from_iter([loc1.clone()]))])
//         );

//         ////////////////////////////////////////////////////////////////////////////////
//         //                                                                            //
//         //  Let's compact the index in order to collapse the negation.                //
//         //                                                                            //
//         //  ```json                                                                   //
//         //  {                                                                         //
//         //      'kwd1' : ['loc1'],                                                    //
//         //      'kwd2' : ['loc2'],                                                    //
//         //  }                                                                         //
//         //  ```                                                                       //
//         //                                                                            //
//         ////////////////////////////////////////////////////////////////////////////////

//         // Before compacting, the Entry Table holds 2 lines since two keywords were indexed.
//         let et_length = index.findex_graph.findex_mm.entry_table.len();
//         assert_eq!(2, et_length);

//         // Before compacting, the Entry Table holds 3 lines since four associations were indexed
//         // but two of them were indexed for the same keyword in the same `add` operations and the
//         // indexed values are small enough to hold in the same line.
//         let ct_length = index.findex_graph.findex_mm.chain_table.len();
//         assert_eq!(3, ct_length);

//         let res = index
//             .compact(&key, &key, &label, &label, 1., &|res| async { Ok(res) })
//             .await;

//         // Ooops we forgot to renew either the key or the label!
//         assert!(res.is_err());

//         // A new label is easier to propagate since this is public information.
//         let new_label = Label::from("second label");

//         index
//             .compact(&key, &key, &label, &new_label, 1f64, &|res| async {
//                 Ok(res)
//             })
//             .await
//             .unwrap();

//         // `new_label` is the new `label`.
//         let label = new_label;

//         // After compacting, the Entry Table still holds 2 lines since each indexed keyword still
//         // holds at least one association.
//         let et_length = index.findex_graph.findex_mm.entry_table.len();
//         assert_eq!(2, et_length);

//         // After compacting, the Chain Table holds 2 lines since the two associations
//         // `kwd1`->`kwd2` and `kwd1`->!`kwd2` collapsed.
//         let ct_length = index.findex_graph.findex_mm.chain_table.len();
//         assert_eq!(2, ct_length);

//         ////////////////////////////////////////////////////////////////////////////////
//         //                                                                            //
//         //  Let's delete the association `loc2`->`kwd2` and compact the index in      //
//         //  order to collapse the negation. Since `kwd2` indexes no more keyword,     //
//         //  it should be removed from the index:                                      //
//         //                                                                            //
//         //  ```json                                                                   //
//         //  {                                                                         //
//         //      'kwd1' : ['loc1'],                                                    //
//         //  }                                                                         //
//         //  ```                                                                       //
//         //                                                                            //
//         ////////////////////////////////////////////////////////////////////////////////

//         index
//             .delete(
//                 &key,
//                 &label,
//                 IndexedValueToKeywordsMap::from_iter([(
//                     IndexedValue::Data(loc2),
//                     HashSet::from_iter([kwd2.clone()]),
//                 )]),
//             )
//             .await
//             .expect("Error while indexing deletions.");

//         // The Entry Table still holds 2 lines since no more keywords were indexed.
//         let et_length = index.findex_graph.findex_mm.entry_table.len();
//         assert_eq!(2, et_length);

//         // The Chain Table holds 3 lines since a new association was indexed.
//         let ct_length = index.findex_graph.findex_mm.chain_table.len();
//         assert_eq!(3, ct_length);

//         let new_label = Label::from("third label");
//         index
//             .compact(&key, &key, &label, &new_label, 1f64, &|res| async {
//                 Ok(res)
//             })
//             .await
//             .unwrap();
//         let label = new_label;

//         // The Entry Table now holds only 1 line since `kwd2` was not associated to any indexed
//         // value anymore.
//         let et_length = index.findex_graph.findex_mm.entry_table.len();
//         assert_eq!(1, et_length);

//         // The Chain Table holds 1 lines since a two associations collapsed.
//         let ct_length = index.findex_graph.findex_mm.chain_table.len();
//         assert_eq!(1, ct_length);

//         ////////////////////////////////////////////////////////////////////////////////
//         //                                                                            //
//         //  It is possible to filter out indexed values from the index during the     //
//         //  compact operation. This is useful when indexed values become obsolete     //
//         //  but the index was not updated. A `data_filter` callback can be given to   //
//         //  the compact operation. It is fed with the indexed values read during      //
//         //  the compact operation. Only those returned are indexed back.              //
//         //                                                                            //
//         //  In this example, the `loc1` value will be filtered out. The index should  //
//         //  then be empty since the `kwd1` will not be associated to any value.       //
//         //                                                                            //
//         //  ```json                                                                   //
//         //  {}                                                                        //
//         //  ```                                                                       //
//         //                                                                            //
//         ////////////////////////////////////////////////////////////////////////////////

//         let new_label = Label::from("fourth label");
//         index
//             .compact(&key, &key, &label, &new_label, 1f64, &|data| async {
//                 let remaining_data = data.into_iter().filter(|v| v != &loc1).collect();
//                 Ok(remaining_data)
//             })
//             .await
//             .unwrap();
//         let _label = new_label;

//         let et_length = index.findex_graph.findex_mm.entry_table.len();
//         assert_eq!(0, et_length);

//         let ct_length = index.findex_graph.findex_mm.chain_table.len();
//         assert_eq!(0, ct_length);
//     }
// }
