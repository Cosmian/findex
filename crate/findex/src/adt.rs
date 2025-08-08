//! We define here the main Abstract Data Types (ADTs) used in this crate,
//! namely:
//! - the index ADT;
//! - the vector ADT;
//!
//! Each of them strive for simplicity and consistency with the classical CS
//! notions.

use std::{collections::HashSet, future::Future, hash::Hash};

/// An index stores *values*, that associate a keyword with a value. All values
/// bound to the same keyword are said to be *indexed under* this keyword.
pub trait IndexADT<Keyword: Send + Hash, Value: Send + Hash> {
    type Error: Send + std::error::Error;

    /// Search the index for the values bound to the given keywords.
    fn search(
        &self,
        keyword: &Keyword,
    ) -> impl Future<Output = Result<HashSet<Value>, Self::Error>>;

    /// Adds the given values to the index.
    fn insert(
        &self,
        keyword: Keyword,
        values: impl Send + IntoIterator<Item = Value>,
    ) -> impl Send + Future<Output = Result<(), Self::Error>>;

    /// Removes the given values from the index.
    fn delete(
        &self,
        keyword: Keyword,
        values: impl Send + IntoIterator<Item = Value>,
    ) -> impl Send + Future<Output = Result<(), Self::Error>>;
}

pub trait VectorADT: Send {
    /// Vectors are homogeneous.
    type Value: Send;

    /// Vector error.
    type Error: Send + std::error::Error;

    /// Pushes the given values at the end of this vector.
    fn push(
        &mut self,
        values: Vec<Self::Value>,
    ) -> impl Send + Future<Output = Result<(), Self::Error>>;

    /// Reads all values stored in this vector.
    fn read(&self) -> impl Send + Future<Output = Result<Vec<Self::Value>, Self::Error>>;
}

/// This trait  extends the functionality of the standard `IndexADT` by providing methods that operate
/// on multiple keywords or entries simultaneously to cut network's overhead and improve performance.
pub trait IndexBatcher<Keyword, Value> {
    type Error: std::error::Error;

    /// Search the index for the values bound to the given keywords.
    fn batch_search(
        &self,
        keywords: Vec<&Keyword>,
    ) -> impl Future<Output = Result<Vec<HashSet<Value>>, Self::Error>>;

    /// Binds each value to their associated keyword in this index.
    fn batch_insert(
        &self,
        entries: Vec<(Keyword, impl Sync + Send + IntoIterator<Item = Value>)>,
    ) -> impl Send + Future<Output = Result<(), Self::Error>>;

    /// Removes the given values from the index.
    fn batch_delete(
        &self,
        entries: Vec<(Keyword, impl Sync + Send + IntoIterator<Item = Value>)>,
    ) -> impl Send + Future<Output = Result<(), Self::Error>>;
}

#[cfg(test)]
pub mod tests {

    pub use vector::*;

    mod vector {
        //! This module defines tests any implementation of the `VectorADT`
        //! interface must pass.

        use crate::adt::VectorADT;

        /// Adding information from different copies of the same vector should
        /// be visible by all copies.
        pub async fn test_vector_sequential<const LENGTH: usize>(
            v: &(impl Clone + Sync + VectorADT<Value = [u8; LENGTH]>),
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
        pub async fn test_vector_concurrent<
            const LENGTH: usize,
            V: 'static + Clone + Sync + VectorADT<Value = [u8; LENGTH]>,
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
                    tokio::spawn(async move {
                        for val in vals {
                            vec.push(vec![val]).await.unwrap();
                        }
                    })
                })
                .collect::<Vec<_>>();
            for h in handles {
                h.await
                    .expect("Join handle failed during test_vector_concurrent");
            }
            let mut res = v.read().await.unwrap();
            let old = res.clone();
            res.sort();
            assert_ne!(old, res);
            assert_eq!(res.len(), n * m);
            assert_eq!(res, values);
        }
    }
}
