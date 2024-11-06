//! We define here the main abstractions used in this crate, namely:
//! - the index ADT;
//! - the vector ADT;
//! - the memory ADT.
//!
//! Each of them strive for simplicity and consistency with the classical CS notions.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    hash::Hash,
};

/// An index stores *bindings*, that associate a keyword with a value. All values bound to the same
/// keyword are said to be *indexed under* this keyword.
pub trait IndexADT<Keyword: Send + Sync + Hash, Value: Send + Sync + Hash> {
    type Error: Send + Sync + std::error::Error;

    /// Search the index for the values bound to the given keywords.
    fn search(
        &self,
        keywords: impl Iterator<Item = Keyword>,
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

pub trait VectorADT: Send + Sync {
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

    /// Write the given words at the given addresses if the word currently stored at the guard
    /// address is the given one, and returns this guard word.
    fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        tasks: Vec<(Self::Address, Self::Word)>,
    ) -> impl Send + Future<Output = Result<Option<Self::Word>, Self::Error>>;
}

#[cfg(test)]
pub(crate) mod tests {

    pub use vector_tests::*;

    mod vector_tests {
        //! This module defines tests any implementation of the VectorADT interface must pass.

        use crate::adt::VectorADT;
        use futures::{executor::block_on, future::join_all};

        /// Adding information from different copies of the same vector should be visible by all
        /// copies.
        pub async fn test_vector_sequential<const LENGTH: usize>(
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

        /// Concurrently adding data to instances of the same vector should not introduce data loss.
        pub async fn test_vector_concurrent<
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
                    tokio::spawn(async move {
                        for val in vals {
                            vec.push(vec![val]).await.unwrap();
                        }
                    })
                })
                .collect::<Vec<_>>();
            for h in join_all(handles).await {
                h.unwrap();
            }
            let mut res = block_on(v.read()).unwrap();
            let old = res.clone();
            res.sort();
            assert_ne!(old, res);
            assert_eq!(res.len(), n * m);
            assert_eq!(res, values);
        }
    }

    mod memory_tests {
        //! This module defines tests any implementation of the MemoryADT interface must pass.
        use std::{
            collections::HashMap,
            future::Future,
            sync::{Arc, Mutex},
        };

        use super::super::MemoryADT;
        use futures::{executor::block_on, future::join_all};

        /// Runs all tests
        pub async fn run_memory_adt_tests<T>(memory: T)
        where
            T: MemoryADT,
            T::Address: std::fmt::Debug + PartialEq + Default,
            T::Word: std::fmt::Debug + PartialEq + Default,
            T::Error: std::fmt::Debug,
        {
            block_on(test_batch_read_empty(&memory));
            block_on(test_single_write_and_read(&memory));
            block_on(test_wrong_guard(&memory));
            block_on(test_correct_guard(&memory));
            block_on(test_multiple_writes(&memory));
        }

        async fn test_batch_read_empty<T>(memory: &T)
        where
            T: MemoryADT,
            T::Address: std::fmt::Debug + PartialEq + Default,
            T::Word: std::fmt::Debug + PartialEq + Default,
            T::Error: std::fmt::Debug,
        {
            let addresses = vec![
                T::Address::default(),
                T::Address::default(),
                T::Address::default(),
            ];
            let result = memory.batch_read(addresses).await.unwrap();
            assert_eq!(result, vec![None, None, None]);
        }

        async fn test_single_write_and_read<T>(memory: &T)
        where
            T: MemoryADT,
            T::Address: std::fmt::Debug + PartialEq + Default,
            T::Word: std::fmt::Debug + PartialEq + Default,
            T::Error: std::fmt::Debug,
        {
            // Write a single value
            let write_result = memory
                .guarded_write(
                    (T::Address::default(), None),
                    vec![(T::Address::default(), T::Word::default())],
                )
                .await
                .unwrap();
            assert_eq!(write_result, None);

            // Retrieve the same value
            let read_result = memory
                .batch_read(vec![T::Address::default()])
                .await
                .unwrap();
            assert_eq!(read_result, vec![Some(T::Word::default())]);
        }

        async fn test_wrong_guard<T>(memory: &T)
        where
            T: MemoryADT,
            T::Address: std::fmt::Debug + PartialEq + Default,
            T::Word: std::fmt::Debug + PartialEq + Default,
            T::Error: std::fmt::Debug,
        {
            // Write something
            memory
                .guarded_write(
                    (T::Address::default(), None),
                    vec![(T::Address::default(), T::Word::default())],
                )
                .await
                .unwrap();

            // Attempt conflicting write with wrong guard value
            let conflict_result = memory
                .guarded_write(
                    (T::Address::default(), None),
                    vec![(T::Address::default(), T::Word::default())],
                )
                .await
                .unwrap();

            // Should return current value and not perform write
            assert_eq!(conflict_result, Some(T::Word::default()));

            // Verify value wasn't changed
            let read_result = memory
                .batch_read(vec![T::Address::default()])
                .await
                .unwrap();
            assert_eq!(read_result, vec![Some(T::Word::default())]);
        }

        async fn test_correct_guard<T>(memory: &T)
        where
            T: MemoryADT,
            T::Address: std::fmt::Debug + PartialEq + Default,
            T::Word: std::fmt::Debug + PartialEq + Default,
            T::Error: std::fmt::Debug,
        {
            // Initial write
            memory
                .guarded_write(
                    (T::Address::default(), None),
                    vec![(T::Address::default(), T::Word::default())],
                )
                .await
                .unwrap();

            // Conditional write with correct guard value
            let write_result = memory
                .guarded_write(
                    (T::Address::default(), Some(T::Word::default())),
                    vec![(T::Address::default(), T::Word::default())],
                )
                .await
                .unwrap();

            assert_eq!(write_result, Some(T::Word::default()));

            // Verify new value
            let read_result = memory
                .batch_read(vec![T::Address::default()])
                .await
                .unwrap();
            assert_eq!(read_result, vec![Some(T::Word::default())]);
        }

        async fn test_multiple_writes<T>(memory: &T)
        where
            T: MemoryADT,
            T::Address: std::fmt::Debug + PartialEq + Default,
            T::Word: std::fmt::Debug + PartialEq + Default,
            T::Error: std::fmt::Debug,
        {
            // Write multiple values atomically
            memory
                .guarded_write(
                    (T::Address::default(), None),
                    vec![
                        (T::Address::default(), T::Word::default()),
                        (T::Address::default(), T::Word::default()),
                        (T::Address::default(), T::Word::default()),
                    ],
                )
                .await
                .unwrap();

            // Read back all values
            let read_result = memory
                .batch_read(vec![
                    T::Address::default(),
                    T::Address::default(),
                    T::Address::default(),
                ])
                .await
                .unwrap();
            assert_eq!(
                read_result,
                vec![
                    Some(T::Word::default()),
                    Some(T::Word::default()),
                    Some(T::Word::default())
                ]
            );
        }

        #[derive(Default, Clone)]
        struct MockMemory {
            storage: Arc<Mutex<HashMap<u8, u8>>>,
        }

        impl MemoryADT for MockMemory {
            type Address = u8;
            type Word = u8;
            type Error = std::io::Error;

            fn batch_read(
                &self,
                addresses: Vec<Self::Address>,
            ) -> impl Send + Future<Output = Result<Vec<Option<Self::Word>>, Self::Error>>
            {
                let storage = Arc::clone(&self.storage);
                async move {
                    let storage = storage.lock().unwrap();
                    Ok(addresses
                        .into_iter()
                        .map(|addr| storage.get(&addr).cloned())
                        .collect())
                }
            }

            fn guarded_write(
                &self,
                guard: (Self::Address, Option<Self::Word>),
                tasks: Vec<(Self::Address, Self::Word)>,
            ) -> impl Send + Future<Output = Result<Option<Self::Word>, Self::Error>> {
                let storage = Arc::clone(&self.storage);
                async move {
                    let mut storage = storage.lock().unwrap();
                    let (guard_addr, guard_value) = guard;
                    let current_value = storage.get(&guard_addr).cloned();
                    if current_value == guard_value {
                        for (addr, word) in tasks {
                            storage.insert(addr, word);
                        }
                    }
                    Ok(current_value)
                }
            }
        }

        #[tokio::test]
        async fn test_sequential_memory_adt_with_mock() {
            let memory = MockMemory::default();
            run_memory_adt_tests(memory).await;
        }

        async fn test_concurrent<T>(memory: T)
        where
            T: MemoryADT<Address = u8, Word = u8> + Send + Sync + 'static + Clone,
            T::Error: std::fmt::Debug,
        {
            // Write multiple values concurrently
            let n: usize = 100;
            let workers: usize = 2;
            let adr_value_pair: Vec<(u8, u8)> = (0..n * workers)
                .map(|i| (i as u8, i as u8))
                .collect::<Vec<_>>();
            let addresses: Vec<u8> = (0..n * workers).map(|i| i as u8).collect::<Vec<_>>();

            let handles = adr_value_pair
                .chunks_exact(workers)
                .map(|vals| {
                    let vals = vals.to_vec();
                    let mem = memory.clone(); // A reference to the same memory

                    // Spawn a new task
                    tokio::spawn(async move {
                        for (adr, val) in vals {
                            mem.guarded_write((T::Address::default(), None), vec![(adr, val)])
                                .await
                                .unwrap();
                        }
                    })
                })
                .collect::<Vec<_>>();

            for h in join_all(handles).await {
                h.unwrap();
            }
            let mut res = block_on(memory.batch_read(addresses.clone())).unwrap();
            let old = res.clone();
            res.sort();
            assert_ne!(old, res);
            assert_eq!(res.len(), n * workers);
            assert_eq!(
                res,
                addresses
                    .into_iter()
                    .map(|opt| Some(opt))
                    .collect::<Vec<_>>()
            );
        }

        #[tokio::test]
        async fn testccr() {
            // TODO : fixme !

            let memory = MockMemory::default();
            test_concurrent(memory).await;
        }
    }
}
