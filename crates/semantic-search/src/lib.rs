mod encoding;
mod error;
mod fuzzy_database;
mod simple_lsh;
mod vector_db;
mod vectors;
mod pyo3;
pub use pyo3::SecureSemanticDB;

pub use encoding::Encoding;
pub use error::Error;
pub use fuzzy_database::FuzzyDB;
pub use simple_lsh::{Parameters as SimpleLshParameters, SimpleLsh};
pub use vector_db::LshVectorDB;
pub use vectors::{F32Vector, F64Vector};

use rand::Rng;

pub trait VectorDB: Send + Sync + Sized {
    /// Parameters used to instantiate a vector database.
    type Parameters;

    /// Type of vector manage by this database.
    type Vector;

    type Score;

    type Error: std::error::Error;

    /// Returns a fresh instance of this vector database.
    fn init(params: Self::Parameters) -> Result<Self, Self::Error>;

    /// Retrieves from the index the (approximate) k vectors that are closest to
    /// the given query.
    fn query(
        &self,
        k: usize,
        query: &Self::Vector,
    ) -> impl std::future::Future<Output = Result<Vec<(Self::Vector, Self::Score)>, Error>>;

    /// Inserts the given point to the index.
    fn insert(&self, point: Self::Vector) -> impl std::future::Future<Output = Result<(), Error>>;
}

pub trait LocalitySensitiveHash {
    /// LSH-specific parameters needed to instantiate it.
    type Parameters;

    /// LSH input.
    type Input;

    /// LSH output.
    ///
    /// Must be hashable to accommodate hash-table-based structures.
    type Output;

    /// Returns a new instance of the locality-sensitive hasher.
    fn init(params: &Self::Parameters, rng: &mut impl Rng) -> Self;

    /// Returns the hash of the given point. This hash implements `IntoIterator`
    /// as some schemes use a multi-probing strategy.
    fn hash(&self, point: &Self::Input) -> impl IntoIterator<Item = Self::Output>;
}

#[cfg(feature = "test-utils")]
pub mod cleartext_index {
    use std::{
        collections::{HashMap, HashSet},
        hash::Hash,
        sync::{Arc, Mutex},
    };

    use cosmian_findex::IndexADT;

    use crate::Error;

    /// Cleartext implementation of an index.
    #[derive(Debug, Clone)]
    pub struct CleartextIndex<K, V>(Arc<Mutex<HashMap<K, HashSet<V>>>>)
    where
        K: Send + Sync + Hash + Eq,
        V: Send + Sync + Hash + Eq + Clone;

    impl<K, V> Default for CleartextIndex<K, V>
    where
        K: Send + Sync + Hash + Eq,
        V: Send + Sync + Hash + Eq + Clone,
    {
        fn default() -> Self {
            Self(Arc::new(Mutex::new(HashMap::default())))
        }
    }

    impl<K, V> IndexADT<K, V> for CleartextIndex<K, V>
    where
        K: Send + Sync + Hash + Eq,
        V: Send + Sync + Hash + Eq + Clone,
    {
        type Error = Error;

        async fn search(&self, keyword: &K) -> Result<HashSet<V>, Self::Error> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(keyword)
                .cloned()
                .unwrap_or_default())
        }

        async fn insert(
            &self,
            keyword: K,
            values: impl Send + IntoIterator<Item = V>,
        ) -> Result<(), Self::Error> {
            let mut index = self.0.lock().unwrap();
            let indexed_values = index.entry(keyword).or_default();
            values.into_iter().for_each(|val| {
                indexed_values.insert(val);
            });
            Ok(())
        }

        async fn delete(
            &self,
            keyword: K,
            values: impl Send + IntoIterator<Item = V>,
        ) -> Result<(), Self::Error> {
            let mut index = self.0.lock().unwrap();
            let indexed_values = index.entry(keyword).or_default();
            values.into_iter().for_each(|val| {
                indexed_values.remove(&val);
            });
            Ok(())
        }
    }
}
