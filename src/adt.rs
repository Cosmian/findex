//! We define here the main Abstract Data Types (ADTs) used in this crate, namely:
//! - the index ADT;
//! - the vector ADT;
//! - the memory ADT.
//!
//! Each of them strive for simplicity and consistency with the classical CS
//! notions.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    hash::Hash,
};

/// An index stores *bindings*, that associate a keyword with a value. All
/// values bound to the same keyword are said to be *indexed under* this
/// keyword.
pub trait IndexADT<Keyword: Send + Sync + Hash, Value: Send + Sync + Hash> {
    type Error: Send + Sync + std::error::Error;

    /// Search the index for the values bound to the given keywords.
    fn search(
        &self,
        keywords: impl Send + Iterator<Item = Keyword>,
    ) -> impl Future<Output = Result<HashMap<Keyword, HashSet<Value>>, Self::Error>>;

    /// Adds the given bindings to the index.
    fn insert(
        &self,
        bindings: impl Sync + Send + Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> impl Send + Future<Output = Result<(), Self::Error>>;

    /// Removes the given bindings from the index.
    fn delete(
        &self,
        bindings: impl Sync + Send + Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> impl Send + Future<Output = Result<(), Self::Error>>;
}

#[allow(clippy::redundant_pub_crate)] // false positive. Used in ovec.rs and findex.rs.
pub(crate) trait VectorADT: Send + Sync {
    /// Vectors are homogeneous.
    type Value: Send + Sync;

    /// Vector error.
    type Error: Send + Sync + std::error::Error;

    /// Pushes the given values at the end of this vector.
    fn push(
        &mut self,
        vs: Vec<Self::Value>,
    ) -> impl Send + Future<Output = Result<(), Self::Error>>;

    /// Reads all values stored in this vector.
    fn read(&self) -> impl Send + Future<Output = Result<Vec<Self::Value>, Self::Error>>;
}

/// A Software Transactional Memory: all operations exposed are atomic.
pub trait MemoryADT {
    /// Address space.
    type Address;

    /// Word space.
    type Word;

    /// Memory error.
    type Error: Send + Sync + std::error::Error;

    /// Reads the words from the given addresses.
    fn batch_read(
        &self,
        a: Vec<Self::Address>,
    ) -> impl Send + Future<Output = Result<Vec<Option<Self::Word>>, Self::Error>>;

    /// Write the given words at the given addresses if the word currently
    /// stored at the guard address is the given one, and returns this guard
    /// word.
    fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        tasks: Vec<(Self::Address, Self::Word)>,
    ) -> impl Send + Future<Output = Result<Option<Self::Word>, Self::Error>>;
}

#[cfg(test)]
pub mod tests {

    #[allow(clippy::redundant_pub_crate)] // false positive. Used in ovec.rs.
    pub(crate) use vector::*;

    mod vector {
        //! This module defines tests any implementation of the `VectorADT`
        //! interface must pass.

        use std::thread::spawn;

        use futures::executor::block_on;

        use crate::adt::VectorADT;

        /// Adding information from different copies of the same vector should
        /// be visible by all copies.
        #[allow(clippy::redundant_pub_crate)] // false positive. Used in ovec.rs.
        pub(crate) async fn test_vector_sequential<const LENGTH: usize>(
            v: &(impl Clone + VectorADT<Value = [u8; LENGTH]>),
        ) {
            let mut v1 = v.clone();
            let mut v2 = v.clone();
            let values = (0..10).map(|n| [n; LENGTH]).collect::<Vec<_>>();
            v1.push(values[..5].to_vec()).await.unwrap();
            v2.push(values[..5].to_vec()).await.unwrap();
            v1.push(values[5..].to_vec()).await.unwrap();
            v2.push(values[5..].to_vec()).await.unwrap();
            assert_eq!(
                [&values[..5], &values[..5], &values[5..], &values[5..]].concat(),
                v.read().await.unwrap()
            );
        }

        /// Concurrently adding data to instances of the same vector should not
        /// introduce data loss.
        #[allow(clippy::redundant_pub_crate)] // false positive. Used in ovec.rs.
        pub(crate) async fn test_vector_concurrent<
            const LENGTH: usize,
            V: 'static + Clone + VectorADT<Value = [u8; LENGTH]>,
        >(
            v: &V,
        ) {
            let n = 100;
            let m = 2;
            let values = (0..n * m).map(|i| [i as u8; LENGTH]).collect::<Vec<_>>();
            let handles = values
                .chunks_exact(m)
                .map(|vals| {
                    let vals = vals.to_vec();
                    let mut vec = v.clone();
                    spawn(|| async move {
                        for val in vals {
                            vec.push(vec![val]).await.unwrap();
                        }
                    })
                })
                .collect::<Vec<_>>();
            for h in handles {
                let () = h.join().unwrap().await;
            }
            let mut res = block_on(v.read()).unwrap();
            res.sort_unstable();
            assert_eq!(res.len(), n * m);
            assert_eq!(res, values);
        }
    }
}
