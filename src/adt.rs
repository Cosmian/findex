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
// ! This module defines tests any implementation of the MemoryADT interface must pass.
#[cfg(feature = "cloudproof")]
pub mod memory_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    // TODO : make those generic
    use futures::future::join_all;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use tokio::spawn;

    use super::MemoryADT;

    pub async fn test_single_write_and_read<T>(memory: &T, seed: [u8; 32])
    where
        T: MemoryADT,
        T::Address: std::fmt::Debug + PartialEq + Default + From<u8>,
        T::Word: std::fmt::Debug + PartialEq + Default + From<u8>,
        T::Error: std::fmt::Debug,
    {
        let mut rng = StdRng::from_seed(seed);

        // Test batch_read of random addresses, expected to be all empty at this point
        let empty_read_result = memory
            .batch_read(vec![
                T::Address::from(rng.gen::<u8>()),
                T::Address::from(rng.gen::<u8>()),
                T::Address::from(rng.gen::<u8>()),
            ])
            .await
            .unwrap();
        let expected_result = vec![None, None, None];
        assert_eq!(
            empty_read_result, expected_result,
            "Test batch_read of empty addresses failed.\nExpected result : {:?}. Got : {:?}. Seed : {:?}",
            expected_result, empty_read_result, seed
        );

        // Generate a random address and a random word that we save
        let random_address = rng.gen::<u8>();
        let random_word = rng.gen::<u8>();

        // Write the word to the address
        let write_result = memory
            .guarded_write(
                (T::Address::from(random_address), None),
                vec![(T::Address::from(random_address), T::Word::from(random_word))],
            )
            .await
            .unwrap();
        assert_eq!(write_result, None);

        // Retrieve the same value
        let read_result: Vec<Option<<T as MemoryADT>::Word>> = memory
            .batch_read(vec![T::Address::from(random_address)])
            .await
            .unwrap();
        assert_eq!(
            read_result,
            vec![Some(T::Word::from(random_word))],
            "test_single_write_and_read failed.\nExpected result : {:?}. Got : {:?} with seed : {:?}",
            vec![Some(T::Word::from(random_word))],
            read_result,
            seed
        );
    }

    pub async fn test_wrong_guard<T>(memory: &T)
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
        assert_eq!(
            conflict_result,
            Some(T::Word::default()),
            "test_wrong_guard failed : {:?}",
            conflict_result
        );

        // Verify value wasn't changed
        let read_result = memory
            .batch_read(vec![T::Address::default()])
            .await
            .unwrap();
        assert_eq!(read_result, vec![Some(T::Word::default())]);
    }

    pub async fn test_correct_guard<T>(memory: &T)
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
        assert_eq!(
            read_result,
            vec![Some(T::Word::default())],
            "test_correct_guard failed : {:?}",
            read_result
        );
    }

    pub async fn test_guarded_write_concurrent<T>(memory: T, seed: [u8; 32])
    where
        T: MemoryADT<Address = u8, Word = u8> + Send + Sync + 'static + Clone,
        T::Error: std::fmt::Debug,
    {
        {
            let mut rng = StdRng::from_seed(seed);

            let n: usize = 100; // number of elements to be written in the memory
            let m: usize = 4; // number of elements written by each concurrent task
            let workers: usize = n / m; // number of concurrent workers
            let guard_address = rng.gen_range(0..n) as u8; // address used as guard
            let write_counter = Arc::new(AtomicUsize::new(0));

            let handles = (0..n)
                .map(|i| i as u8)
                .collect::<Vec<_>>()
                // Split the values into chunks of size m
                .chunks_exact(workers)
                .map(|vals| {
                    let vals = vals.to_vec();
                    let mem = memory.clone(); // A reference to the same memory
                    let counter_ref = write_counter.clone();
                    // Spawn a new task
                    spawn(async move {
                        for _ in vals {
                            // All concurrent tasks will try to write to write to the same address
                            // As the operation is atomic, only one of them should succeed.
                            let current_value = mem
                                .guarded_write((guard_address, None), vec![(guard_address, 1)])
                                .await
                                .unwrap();
                            if current_value.is_none() {
                                counter_ref.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();

            for h in join_all(handles).await {
                h.unwrap();
            }

            assert_eq!(
                write_counter.load(Ordering::Relaxed),
                1,
                "{:?} threads were able to write to memory. Only one should have been able to, is batch_write atomic ?\n Debug seed : {:?}.", write_counter.load(Ordering::Relaxed), seed
            );
        }
    }
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
        use futures::executor::block_on;

        use super::super::memory_tests::{
            test_correct_guard, test_guarded_write_concurrent, test_single_write_and_read,
            test_wrong_guard,
        };

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
            block_on(test_single_write_and_read(&memory, rand::random()));
            block_on(test_wrong_guard(&memory));
            block_on(test_correct_guard(&memory));
        }

        #[tokio::test]
        async fn test_concurrency_with_mock() {
            let memory = MockMemory::default();
            test_guarded_write_concurrent(memory, rand::random()).await;
        }
    }
}
