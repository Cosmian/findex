//! This module defines tests any implementation of the MemoryADT interface must
//! pass.
//!
//! The given seeds are used to initialize the random generators used in the
//! test, thus allowing for reproducibility. In particular, all addresses are
//! randomly generated, which should guarantee thread-safety provided a
//! random-enough seed is given.
//!
//! Both addresses and words are 16-byte long.

use crate::{ADDRESS_LENGTH, MemoryADT};
use cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use std::{fmt::Debug, future::Future};

pub const SEED_LENGTH: usize = 32;

pub fn gen_seed() -> [u8; SEED_LENGTH] {
    let mut rng = CsRng::from_entropy();
    let mut bytes = [0; SEED_LENGTH];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn gen_bytes<const BYTES_LENGTH: usize>(rng: &mut impl RngCore) -> [u8; BYTES_LENGTH] {
    let mut bytes = [0; BYTES_LENGTH];
    rng.fill_bytes(&mut bytes);
    bytes
}

fn u128_to_array<const WORD_LENGTH: usize>(u: u128) -> [u8; WORD_LENGTH] {
    let mut bytes = [0u8; WORD_LENGTH];
    bytes[..16].copy_from_slice(&u.to_be_bytes());
    bytes
}

fn word_to_array<const WORD_LENGTH: usize>(word: [u8; WORD_LENGTH]) -> Result<u128, &'static str> {
    if WORD_LENGTH < 16 {
        return Err("WORD_LENGTH must be at least 16 bytes");
    }
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&word[..16]);
    Ok(u128::from_be_bytes(bytes))
}

/// Tests the basic write and read operations of a Memory ADT implementation.
///
/// This function first attempts reading empty addresses, then performing a
/// guarded write, and finally validating the written value.
pub async fn test_single_write_and_read<const WORD_LENGTH: usize, Memory>(
    memory: &Memory,
    seed: [u8; SEED_LENGTH],
) where
    Memory: Send + Sync + MemoryADT,
    Memory::Address: Send + Clone + From<[u8; ADDRESS_LENGTH]>,
    Memory::Word: Send + Debug + Clone + PartialEq + From<[u8; WORD_LENGTH]>,
    Memory::Error: std::error::Error,
{
    let mut rng = CsRng::from_seed(seed);
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
pub async fn test_wrong_guard<const WORD_LENGTH: usize, Memory>(
    memory: &Memory,
    seed: [u8; SEED_LENGTH],
) where
    Memory: Send + Sync + MemoryADT,
    Memory::Address: Send + Clone + From<[u8; ADDRESS_LENGTH]>,
    Memory::Word: Send + Debug + Clone + PartialEq + From<[u8; WORD_LENGTH]>,
    Memory::Error: Send + std::error::Error,
{
    let mut rng = CsRng::from_seed(seed);

    let a = Memory::Address::from(gen_bytes(&mut rng));
    let w = Memory::Word::from(gen_bytes(&mut rng));

    memory
        .guarded_write((a.clone(), None), vec![(a.clone(), w.clone())])
        .await
        .unwrap();

    let conflict_result = memory
        .guarded_write(
            (a.clone(), None),
            vec![(a.clone(), Memory::Word::from(gen_bytes(&mut rng)))],
        )
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

/// Tests operations on repeated addresses in memory implementations.
///
/// This test verifies the behavior when the same address is used multiple times:
/// 1. Writes a value to an address and then confirms it can be read back multiple times consistently
/// 2. Performs multiple writes to the same address with a correct guard
/// 3. Verifies that one of the written values is properly stored
pub async fn test_rw_same_address<const WORD_LENGTH: usize, Memory>(
    memory: &Memory,
    seed: [u8; SEED_LENGTH],
) where
    Memory: Send + Sync + MemoryADT,
    Memory::Address: Send + Clone + From<[u8; ADDRESS_LENGTH]>,
    Memory::Word: Send + Debug + Clone + PartialEq + From<[u8; WORD_LENGTH]>,
    Memory::Error: Send + std::error::Error,
{
    const REPETITION: usize = 5;
    let mut rng = CsRng::from_seed(seed);

    let a = Memory::Address::from(gen_bytes(&mut rng));
    let w = Memory::Word::from(gen_bytes(&mut rng));

    memory
        .guarded_write((a.clone(), None), vec![(a.clone(), w.clone())])
        .await
        .unwrap();

    // try to read that same address multiple times
    let read_result = memory
        .batch_read(vec![a.clone(); REPETITION])
        .await
        .unwrap();

    assert_eq!(
        read_result,
        vec![Some(w.clone()); REPETITION],
        "test_collisions failed. Expected all reads to return the same value. Got : {:?}. Debug \
         seed : {:?}",
        read_result,
        seed
    );

    // try to write multiple values to the same address with a guard that should pass
    let values = (0..REPETITION)
        .map(|_| Memory::Word::from(gen_bytes(&mut rng)))
        .collect::<Vec<_>>();
    let same_adr_write = memory
        .guarded_write(
            (a.clone(), Some(w.clone())),
            (0..values.len())
                .map(|i| (a.clone(), values[i].clone()))
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap();

    assert_eq!(
        same_adr_write,
        Some(w.clone()),
        "test_wrong_guard failed.\nExpected value {:?} after write. Got : {:?}.\nDebug seed : {:?}",
        same_adr_write,
        Some(w),
        seed
    );

    let written_value = memory.batch_read(vec![a.clone()]).await.unwrap();

    assert!(
        values.iter().any(|v| Some(v.clone()) == written_value[0]),
        "Value not found in the written values list. Got: {:?}, Values: {:?}",
        written_value,
        values
    );
}

/// Trait for spawning async tasks in a runtime-agnostic way
pub trait TaskSpawner: Send + Sync {
    type JoinHandle<T: Send + 'static>: Future<Output = Result<T, Self::JoinError>> + Send;
    type JoinError: std::error::Error + Send;

    fn spawn<F>(future: F) -> Self::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}

pub struct TokioSpawner;

impl TaskSpawner for TokioSpawner {
    type JoinHandle<T: Send + 'static> = tokio::task::JoinHandle<T>;
    type JoinError = tokio::task::JoinError;

    fn spawn<F>(future: F) -> Self::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        tokio::spawn(future)
    }
}

/// Tests concurrent guarded write operations on a Memory ADT implementation.
///
/// Spawns multiple threads to perform concurrent counter increments.
/// Uses retries to handle write contention between threads.
/// Verifies the final counter matches the total number of threads.
///
///
/// # Arguments
///
/// * `memory` - The Memory ADT implementation to test.
/// * `seed` - The seed used to initialize the random number generator.
/// * `n_threads` - The number of threads to spawn. If None, defaults to 100.
pub async fn test_guarded_write_concurrent<const WORD_LENGTH: usize, Memory, S>(
    memory: &Memory,
    seed: [u8; SEED_LENGTH],
    n_threads: Option<usize>,
) where
    Memory: 'static + Send + Sync + MemoryADT + Clone,
    Memory::Address: Send + From<[u8; ADDRESS_LENGTH]>,
    Memory::Word:
        Send + Debug + PartialEq + From<[u8; WORD_LENGTH]> + Into<[u8; WORD_LENGTH]> + Clone,
    Memory::Error: Send + std::error::Error,
    S: TaskSpawner,
{
    // A worker increment N times the counter m[a].
    async fn worker<const WORD_LENGTH: usize, Memory>(
        m: Memory,
        a: [u8; ADDRESS_LENGTH],
    ) -> Result<(), Memory::Error>
    where
        Memory: 'static + Send + Sync + MemoryADT + Clone,
        Memory::Address: Send + From<[u8; ADDRESS_LENGTH]>,
        Memory::Word:
            Send + Debug + PartialEq + From<[u8; WORD_LENGTH]> + Into<[u8; WORD_LENGTH]> + Clone,
    {
        let mut cnt = 0u128;
        for _ in 0..M {
            loop {
                let guard = if 0 == cnt {
                    None
                } else {
                    Some(Memory::Word::from(u128_to_array(cnt)))
                };

                let new_cnt = cnt + 1;
                let cur_cnt = m
                    .guarded_write(
                        (a.into(), guard),
                        vec![(a.into(), Memory::Word::from(u128_to_array(new_cnt)))],
                    )
                    .await?
                    .map(|w| word_to_array(w.into()).unwrap())
                    .unwrap_or_default();

                if cnt == cur_cnt {
                    cnt = new_cnt;
                    break;
                } else {
                    cnt = cur_cnt;
                }
            }
        }
        Ok(())
    }

    let n: usize = n_threads.unwrap_or(100); // number of workers
    const M: usize = 10; // number of increments per worker
    let mut rng = CsRng::from_seed(seed);
    let a = gen_bytes(&mut rng);

    let handles = (0..n)
        .map(|_| {
            let m = memory.clone();
            S::spawn(worker(m, a))
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    let final_count = memory.batch_read(vec![a.into()]).await.unwrap()[0]
        .clone()
        .expect("Counter should exist");

    assert_eq!(
        word_to_array(final_count.clone().into()).unwrap(),
        (n * M) as u128,
        "test_guarded_write_concurrent failed. Expected the counter to be at {:?}, found \
             {:?}.\nDebug seed : {:?}.",
        (n * M) as u128,
        word_to_array(final_count.into()).unwrap(),
        seed
    );
}
