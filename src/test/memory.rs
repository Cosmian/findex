// ! This module defines tests any implementation of the MemoryADT interface must pass.
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::MemoryADT;

pub async fn test_single_write_and_read<T>(memory: &T, seed: [u8; 32])
where
    T: MemoryADT,
    T::Address: std::fmt::Debug + PartialEq + From<u128>,
    T::Word: std::fmt::Debug + PartialEq + From<u128>,
    T::Error: std::error::Error,
{
    let mut rng = StdRng::from_seed(seed);

    // Test batch_read of random addresses, expected to be all empty at this point
    let empty_read_result = memory
        .batch_read(vec![
            T::Address::from(rng.gen::<u128>()),
            T::Address::from(rng.gen::<u128>()),
            T::Address::from(rng.gen::<u128>()),
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
    let random_address = rng.gen::<u128>();
    let random_word = rng.gen::<u128>();

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
    let expected_result = vec![Some(T::Word::from(random_word))];
    assert_eq!(
            read_result,
            expected_result,
            "test_single_write_and_read failed.\nExpected result : {:?}, got : {:?}.\nDebug seed : {:?}",
            expected_result,
            read_result,
            seed
        );
}

pub async fn test_wrong_guard<T>(memory: &T, seed: [u8; 32])
where
    T: MemoryADT,
    T::Address: std::fmt::Debug + PartialEq + From<u128>,
    T::Word: std::fmt::Debug + PartialEq + From<u128>,
    T::Error: std::error::Error,
{
    let mut rng = StdRng::from_seed(seed);
    let random_address = rng.gen::<u128>();
    let word_to_write = rng.gen::<u128>();

    // Write something to a random address
    memory
        .guarded_write(
            (T::Address::from(random_address), None),
            vec![(
                T::Address::from(random_address),
                T::Word::from(word_to_write),
            )],
        )
        .await
        .unwrap();

    // Attempt conflicting write with wrong guard value
    let conflict_result = memory
        .guarded_write(
            (T::Address::from(random_address), None),
            vec![(
                T::Address::from(random_address),
                T::Word::from(rng.gen::<u128>()),
            )],
        )
        .await
        .unwrap();

    // Should return current value and not perform write
    assert_eq!(
        conflict_result,
        Some(T::Word::from(word_to_write)),
        "test_wrong_guard failed.\nExpected value {:?} after write. Got : {:?}.\nDebug seed : {:?}",
        conflict_result,
        Some(T::Word::from(word_to_write)),
        seed
    );

    // Verify value wasn't changed
    let read_result = memory
        .batch_read(vec![T::Address::from(random_address)])
        .await
        .unwrap();
    assert_eq!(
        vec![Some(T::Word::from(word_to_write)),],
        read_result,
        "test_wrong_guard failed. Value was overwritten, violating the guard. Expected : {:?}, got : {:?}. Debug seed : {:?}",
        vec![Some(T::Word::from(word_to_write)),],
        read_result,
        seed
    );
}

pub async fn test_guarded_write_concurrent<T>(memory: T, seed: [u8; 32])
where
    T: MemoryADT<Address = u128, Word = u128> + Send + 'static + Clone,
    T::Error: std::error::Error,
{
    {
        const N: usize = 1000; // number of threads
        let mut rng = StdRng::from_seed(seed);
        let guard_address = rng.gen::<u128>(); // address used as guard

        let handles: Vec<_> = (0..N)
            .map(|_| {
                let mem = memory.clone();
                std::thread::spawn(move || async move {
                    // All concurrent tasks will try to write to the same address
                    // As the operation is atomic, only one of them should succeed and return true.
                    mem.guarded_write((guard_address, None), vec![(guard_address, 1)])
                        .await
                        .unwrap()
                        .is_none()
                })
            })
            .collect::<Vec<_>>();

        let mut write_counter = 0;
        for handle in handles {
            write_counter += if handle.join().unwrap().await { 1 } else { 0 };
        }

        assert_eq!(
                write_counter,
                1,
                "{:?} threads were able to write to memory. Only one should have been able to, is batch_write atomic ?\n Debug seed : {:?}.", write_counter, seed
            );
    }
}
