//! This module defines tests any implementation of the MemoryADT interface must
//! pass.
//!
//! The given seeds are used to initialize the random generators used in the
//! test, thus allowing for reproducibility. In particular, all addresses are
//! randomly generated, which should guarantee thread-safety provided a
//! random-enough seed is given.
//!
//! Both addresses and words are 16-byte long.

use crate::MemoryADT;
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use std::fmt::Debug;

fn gen_bytes(rng: &mut impl RngCore) -> [u8; 16] {
    let mut bytes = [0; 16];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Tests the basic write and read operations of a Memory ADT implementation.
///
/// This function first attempts reading empty addresses, then performing a
/// guarded write, and finally validating the written value.
pub async fn test_single_write_and_read<Memory>(memory: &Memory, seed: [u8; 32])
where
    Memory: Send + Sync + MemoryADT,
    Memory::Address: Send + Clone + From<[u8; 16]>,
    Memory::Word: Send + Debug + Clone + PartialEq + From<[u8; 16]>,
    Memory::Error: std::error::Error,
{
    let mut rng = StdRng::from_seed(seed);
    let empty_read_result = memory
        .batch_read(vec![
            Memory::Address::from(gen_bytes(&mut rng)),
            Memory::Address::from(gen_bytes(&mut rng)),
            Memory::Address::from(gen_bytes(&mut rng)),
        ])
        .await
        .unwrap();
    let expected_result = vec![None, None, None];
    assert_eq!(
        empty_read_result, expected_result,
        "Test batch_read of empty addresses failed.\nExpected result : {expected_result:?}. Got : \
         {empty_read_result:?}. Seed : {seed:?}"
    );

    let a = Memory::Address::from(gen_bytes(&mut rng));
    let w = Memory::Word::from(gen_bytes(&mut rng));

    let write_result = memory
        .guarded_write((a.clone(), None), vec![(a.clone(), w.clone())])
        .await
        .unwrap();
    assert_eq!(write_result, None);

    let read_result = memory.batch_read(vec![a]).await.unwrap();
    let expected_result = vec![Some(w)];
    assert_eq!(
        read_result, expected_result,
        "test_single_write_and_read failed.\nExpected result : {expected_result:?}, got : \
         {read_result:?}.\nDebug seed : {seed:?}"
    );
}

/// Tests guard violation handling in memory implementations.
///
/// Attempts to write with a None guard to an address containing a value.
/// Verifies that the original value is preserved and the write fails.
pub async fn test_wrong_guard<Memory>(memory: &Memory, seed: [u8; 32])
where
    Memory: Send + Sync + MemoryADT,
    Memory::Address: Send + Clone + From<[u8; 16]>,
    Memory::Word: Send + Debug + Clone + PartialEq + From<[u8; 16]>,
    Memory::Error: Send + std::error::Error,
{
    let mut rng = StdRng::from_seed(seed);

    let a = Memory::Address::from(gen_bytes(&mut rng));
    let w = Memory::Word::from(gen_bytes(&mut rng));

    memory
        .guarded_write((a.clone(), None), vec![(a.clone(), w.clone())])
        .await
        .unwrap();

    let conflict_result = memory
        .guarded_write((a.clone(), None), vec![(
            a.clone(),
            Memory::Word::from(rng.random::<u128>().to_be_bytes()),
        )])
        .await
        .unwrap();

    assert_eq!(
        conflict_result,
        Some(w.clone()),
        "test_wrong_guard failed.\nExpected value {:?} after write. Got : {:?}.\nDebug seed : {:?}",
        conflict_result,
        Some(w),
        seed
    );

    let read_result = memory.batch_read(vec![a]).await.unwrap();
    assert_eq!(
        vec![Some(w.clone()),],
        read_result,
        "test_wrong_guard failed. Value was overwritten, violating the guard. Expected : {:?}, \
         got : {:?}. Debug seed : {:?}",
        vec![Some(w),],
        read_result,
        seed
    );
}

/// Tests concurrent guarded write operations on a Memory ADT implementation.
///
/// Spawns multiple threads to perform concurrent counter increments.
/// Uses retries to handle write contention between threads.
/// Verifies the final counter matches the total number of threads.
pub async fn test_guarded_write_concurrent<Memory>(memory: &Memory, seed: [u8; 32])
where
    Memory: 'static + Send + Sync + MemoryADT + Clone,
    Memory::Address: Send + From<[u8; 16]>,
    Memory::Word: Send + Debug + PartialEq + From<[u8; 16]> + Into<[u8; 16]> + Clone + Default,
    Memory::Error: Send + std::error::Error,
{
    {
        const N: usize = 100;
        let mut rng = StdRng::from_seed(seed);
        let a = gen_bytes(&mut rng);

        // A worker increment N times the counter m[a].
        let worker = |m: Memory, a: [u8; 16]| async move {
            let mut cnt = 0u128;
            for _ in 0..N {
                loop {
                    let guard = if 0 == cnt {
                        None
                    } else {
                        Some(Memory::Word::from(cnt.to_be_bytes()))
                    };

                    let new_cnt = cnt + 1;
                    let cur_cnt = m
                        .guarded_write((a.into(), guard), vec![(
                            a.into(),
                            Memory::Word::from(new_cnt.to_be_bytes()),
                        )])
                        .await
                        .unwrap()
                        .map(|w| <u128>::from_be_bytes(w.into()))
                        .unwrap_or_default();

                    if cnt == cur_cnt {
                        cnt = new_cnt;
                        break;
                    } else {
                        cnt = cur_cnt;
                    }
                }
            }
        };

        // Spawn N concurrent workers.
        let handles: Vec<_> = (0..N)
            .map(|_| {
                let m = memory.clone();
                std::thread::spawn(move || worker(m, a))
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
            (N * N) as u128,
            "test_guarded_write_concurrent failed. Expected the counter to be at {:?}, found \
             {:?}.\nDebug seed : {:?}.",
            N as u128,
            u128::from_be_bytes(final_count.into()),
            seed
        );
    }
}
