// ! This module defines tests any implementation of the MemoryADT interface must pass.
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::MemoryADT;

pub async fn test_single_write_and_read<T>(memory: &T, seed: [u8; 32])
where
    T: MemoryADT,
    T::Address: std::fmt::Debug + PartialEq + From<[u8; 16]>,
    T::Word: std::fmt::Debug + PartialEq + From<[u8; 16]>,
    T::Error: std::error::Error,
{
    let mut rng = StdRng::from_seed(seed);

    // Test batch_read of random addresses, expected to be all empty at this point
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
            "Test batch_read of empty addresses failed.\nExpected result : {:?}. Got : {:?}. Seed : {:?}",
            expected_result, empty_read_result, seed
        );

    // Generate a random address and a random word that we save
    let random_address = rng.gen::<u128>().to_be_bytes();
    let random_word = rng.gen::<u128>().to_be_bytes();

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
    T::Address: std::fmt::Debug + PartialEq + From<[u8; 16]>,
    T::Word: std::fmt::Debug + PartialEq + From<[u8; 16]>,
    T::Error: std::error::Error,
{
    let mut rng = StdRng::from_seed(seed);
    let random_address = rng.gen::<u128>().to_be_bytes();
    let word_to_write = rng.gen::<u128>().to_be_bytes();

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
                T::Word::from(rng.gen::<u128>().to_be_bytes()),
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
    T: MemoryADT + Send + 'static + Clone,
    T::Address: std::fmt::Debug + PartialEq + From<[u8; 16]> + Send,
    T::Word: std::fmt::Debug + PartialEq + From<[u8; 16]> + Into<[u8; 16]> + Send + Clone + Default,
    T::Error: std::error::Error,
{
    {
        const N: usize = 1000; // number of threads
        let mut rng = StdRng::from_seed(seed);
        let a = rng.gen::<u128>().to_be_bytes(); // Random address for a counter

        let handles: Vec<_> = (0..N)
            .map(|_| {
                let mem = memory.clone();
                std::thread::spawn(move || async move {
                    let mut old_cnt = None;
                    loop {
                        // Try to increment
                        let cur_cnt = mem
                            .guarded_write(
                                (a.into(), old_cnt.clone()),
                                vec![(
                                    a.into(),
                                    (u128::from_be_bytes(
                                        old_cnt.clone().unwrap_or_default().into(),
                                    ) + 1)
                                        .to_be_bytes()
                                        .into(),
                                )],
                            )
                            .await
                            .unwrap();
                        if cur_cnt == old_cnt {
                            return; // Successfully incremented, quit
                        } else {
                            old_cnt = cur_cnt; // Guard failed, retry with the new value
                        }
                    }
                })
            })
            .collect();

        // wait for all threads to finish
        for handle in handles {
            handle.join().unwrap().await;
        }

        let final_count = memory.batch_read(vec![a.into()]).await.unwrap()[0]
            .clone()
            .expect("Counter should exist");

        assert_eq!(
            u128::from_be_bytes(final_count.clone().into()), N as u128,
            "test_guarded_write_concurrent failed. Expected the counter to be at {:?}, found {:?}.\nDebug seed : {:?}.",
            N as u128, u128::from_be_bytes(final_count.into()), seed
        );
    }
}
