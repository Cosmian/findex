// ! This module defines tests any implementation of the MemoryADT interface
// must pass.
use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::MemoryADT;

/// Tests the basic write and read operations of a Memory ADT implementation.
///
/// This function verifies the memory operations by first checking empty addresses,
/// then performing a guarded write, and finally validating the written value.
///
/// # Arguments
///
/// * `memory` - Reference to the Memory ADT implementation
/// * `seed` - 32-byte seed for reproducible random generation
///
/// # Type Parameters
///
/// * `T` - The Memory ADT implementation being tested
///
/// # Requirements
///
/// The type `T` must implement:
/// * `MemoryADT + Send + Sync`
/// * `T::Address: Debug + PartialEq + From<[u8; 16]> + Send`
/// * `T::Word: Debug + PartialEq + From<[u8; 16]> + Send`
/// * `T::Error: std::error::Error + Send`
///
/// # Examples
///
/// ```no_run
/// # let memory = // your memory implementation
/// # let seed = [0u8; 32];
/// # test_single_write_and_read(&memory, seed).await;
/// ```
pub async fn test_single_write_and_read<T>(memory: &T, seed: [u8; 32])
where
    T: MemoryADT + Send + Sync,
    T::Address: std::fmt::Debug + PartialEq + From<[u8; 16]> + Send,
    T::Word: std::fmt::Debug + PartialEq + From<[u8; 16]> + Send,
    T::Error: std::error::Error + Send,
{
    let mut rng = StdRng::from_seed(seed);

    let empty_read_result = memory
        .batch_read(vec![
            T::Address::from(rng.gen::<u128>().to_be_bytes()),
            T::Address::from(rng.gen::<u128>().to_be_bytes()),
            T::Address::from(rng.gen::<u128>().to_be_bytes()),
        ])
        .await
        .unwrap();
    let expected_result = vec![None, None, None];
    assert_eq!(
        empty_read_result, expected_result,
        "Test batch_read of empty addresses failed.\nExpected result : {expected_result:?}. Got : \
         {empty_read_result:?}. Seed : {seed:?}"
    );

    let random_address = rng.gen::<u128>().to_be_bytes();
    let random_word = rng.gen::<u128>().to_be_bytes();

    let write_result = memory
        .guarded_write((T::Address::from(random_address), None), vec![(
            T::Address::from(random_address),
            T::Word::from(random_word),
        )])
        .await
        .unwrap();
    assert_eq!(write_result, None);

    let read_result: Vec<Option<<T as MemoryADT>::Word>> = memory
        .batch_read(vec![T::Address::from(random_address)])
        .await
        .unwrap();
    let expected_result = vec![Some(T::Word::from(random_word))];
    assert_eq!(
        read_result, expected_result,
        "test_single_write_and_read failed.\nExpected result : {expected_result:?}, got : \
         {read_result:?}.\nDebug seed : {seed:?}"
    );
}

/// Verifies that the memory implementation correctly handles guard violations
/// by attempting to write with a None guard to an address that already contains a value.
/// The test ensures the original value is preserved and the write operation fails appropriately.
///
/// # Arguments
///
/// * `memory` - Reference to the Memory ADT implementation
/// * `seed` - 32-byte seed for reproducible random generation
///
/// # Type Parameters
///
/// * `T` - The Memory ADT implementation being tested
///
/// # Requirements
///
/// The type `T` must implement:
/// * `MemoryADT + Send + Sync`
/// * `T::Address: Debug + PartialEq + From<[u8; 16]> + Send`
/// * `T::Word: Debug + PartialEq + From<[u8; 16]> + Send`
/// * `T::Error: std::error::Error + Send`
///
/// # Examples
///
/// ```no_run
/// # let memory = // your memory implementation
/// # let seed = [0u8; 32];
/// # test_wrong_guard(&memory, seed).await;
/// ```
pub async fn test_wrong_guard<T>(memory: &T, seed: [u8; 32])
where
    T: MemoryADT + Send + Sync,
    T::Address: std::fmt::Debug + PartialEq + From<[u8; 16]> + Send,
    T::Word: std::fmt::Debug + PartialEq + From<[u8; 16]> + Send,
    T::Error: std::error::Error + Send,
{
    let mut rng = StdRng::from_seed(seed);
    let random_address = rng.gen::<u128>().to_be_bytes();
    let word_to_write = rng.gen::<u128>().to_be_bytes();

    memory
        .guarded_write((T::Address::from(random_address), None), vec![(
            T::Address::from(random_address),
            T::Word::from(word_to_write),
        )])
        .await
        .unwrap();

    let conflict_result = memory
        .guarded_write((T::Address::from(random_address), None), vec![(
            T::Address::from(random_address),
            T::Word::from(rng.gen::<u128>().to_be_bytes()),
        )])
        .await
        .unwrap();

    assert_eq!(
        conflict_result,
        Some(T::Word::from(word_to_write)),
        "test_wrong_guard failed.\nExpected value {:?} after write. Got : {:?}.\nDebug seed : {:?}",
        conflict_result,
        Some(T::Word::from(word_to_write)),
        seed
    );

    let read_result = memory
        .batch_read(vec![T::Address::from(random_address)])
        .await
        .unwrap();
    assert_eq!(
        vec![Some(T::Word::from(word_to_write)),],
        read_result,
        "test_wrong_guard failed. Value was overwritten, violating the guard. Expected : {:?}, \
         got : {:?}. Debug seed : {:?}",
        vec![Some(T::Word::from(word_to_write)),],
        read_result,
        seed
    );
}

/// Tests concurrent guarded write operations on a Memory ADT implementation.
/// It spawns N threads that each try to increment the counter, handling contention through retries,
/// and validates that the final counter value equals the number of threads.
///
/// # Arguments
///
/// * `memory` - Reference to the Memory ADT implementation that can be cloned
/// * `seed` - 32-byte seed for reproducible random generation
///
/// # Type Parameters
///
/// * `T` - The Memory ADT implementation being tested
///
/// # Requirements
///
/// The type `T` must implement:
/// * `MemoryADT + Send + Sync + 'static + Clone`
/// * `T::Address: Debug + PartialEq + From<[u8; 16]> + Send`
/// * `T::Word: Debug + PartialEq + From<[u8; 16]> + Into<[u8; 16]> + Send + Clone + Default`
/// * `T::Error: std::error::Error`
///
/// # Examples
///
/// ```no_run
/// # let memory = // your memory implementation
/// # let seed = [0u8; 32];
/// # test_guarded_write_concurrent(&memory, seed).await;
/// ```
pub async fn test_guarded_write_concurrent<T>(memory: &T, seed: [u8; 32])
where
    T: MemoryADT + Send + Sync + 'static + Clone,
    T::Address: std::fmt::Debug + PartialEq + From<[u8; 16]> + Send,
    T::Word: std::fmt::Debug + PartialEq + From<[u8; 16]> + Into<[u8; 16]> + Send + Clone + Default,
    T::Error: std::error::Error,
{
    {
        const N: usize = 1000;
        let mut rng = StdRng::from_seed(seed);
        let a = rng.gen::<u128>().to_be_bytes();

        let handles: Vec<_> = (0..N)
            .map(|_| {
                let mem = memory.clone();
                std::thread::spawn(move || async move {
                    let mut old_cnt = None;
                    loop {
                        let cur_cnt = mem
                            .guarded_write((a.into(), old_cnt.clone()), vec![(
                                a.into(),
                                (u128::from_be_bytes(old_cnt.clone().unwrap_or_default().into())
                                    + 1)
                                .to_be_bytes()
                                .into(),
                            )])
                            .await
                            .unwrap();
                        if cur_cnt == old_cnt {
                            return;
                        } else {
                            old_cnt = cur_cnt;
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap().await;
        }

        let final_count = memory.batch_read(vec![a.into()]).await.unwrap()[0]
            .clone()
            .expect("Counter should exist");

        assert_eq!(
            u128::from_be_bytes(final_count.clone().into()),
            N as u128,
            "test_guarded_write_concurrent failed. Expected the counter to be at {:?}, found \
             {:?}.\nDebug seed : {:?}.",
            N as u128,
            u128::from_be_bytes(final_count.into()),
            seed
        );
    }
}
