//! This module implements a simple vector, defined as a data-structure that preserves the
//! following invariant:
//!
//! `I_v`: the value of the counter stored at the vector address is equal to the number of values
//! stored in this vector; these values are of homogeneous type and stored in contiguous memory words.
//!
//! This implementation is based on the assumption that an infinite array starting at the vector's
//! address has been allocated, and thus stores values after the header:
//!
//! ```txt
//! +------------+-----+-----+-----+
//! | header (h) | v_0 | ... | v_n |
//! +------------+-----+-----+-----+
//!      a         a+1   ...  a+n+1
//! ```

use cosmian_findex_memories::MemoryADT;

use crate::{adt::VectorADT, error::Error};
use std::{fmt::Debug, hash::Hash, ops::Add};

/// Headers contain a counter of the number of values stored in the vector.
// TODO: header could store metadata (e.g. sparsity budget)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Header {
    pub(crate) cnt: u64,
}

impl<const WORD_LENGTH: usize> TryFrom<&Header> for [u8; WORD_LENGTH] {
    type Error = String;

    fn try_from(header: &Header) -> Result<Self, Self::Error> {
        if WORD_LENGTH < 8 {
            return Err("insufficient word length: should be at least 16 bytes".to_string());
        }
        let mut res = [0; WORD_LENGTH];
        res[..8].copy_from_slice(&header.cnt.to_be_bytes());
        Ok(res)
    }
}

impl<const WORD_LENGTH: usize> TryFrom<Header> for [u8; WORD_LENGTH] {
    type Error = String;

    fn try_from(value: Header) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 8 {
            return Err(format!(
                "value to short to be converted to header: need {}, got {}",
                16,
                value.len()
            ));
        }
        let cnt = <[u8; 8]>::try_from(&value[..8]).expect("length is correct");
        Ok(Self {
            cnt: u64::from_be_bytes(cnt),
        })
    }
}

/// Implementation of a vector in an infinite array.
#[derive(Debug)]
pub struct IVec<const WORD_LENGTH: usize, Memory: MemoryADT<Word = [u8; WORD_LENGTH]>> {
    // backing array address
    a: Memory::Address,
    m: Memory,
}

impl<
    const WORD_LENGTH: usize,
    Address: Clone,
    Memory: Clone + MemoryADT<Address = Address, Word = [u8; WORD_LENGTH]>,
> Clone for IVec<WORD_LENGTH, Memory>
{
    fn clone(&self) -> Self {
        Self {
            a: self.a.clone(),
            m: self.m.clone(),
        }
    }
}

impl<
    const WORD_LENGTH: usize,
    Address: Hash + Eq + Debug + Clone + Add<u64, Output = Address>,
    Memory: Clone + MemoryADT<Address = Address, Word = [u8; WORD_LENGTH]>,
> IVec<WORD_LENGTH, Memory>
{
    /// (Lazily) instantiates a new vector at this address in this memory: no value is written
    /// before the first push.
    pub const fn new(a: Address, m: Memory) -> Self {
        Self { a, m }
    }
}

impl<
    const WORD_LENGTH: usize,
    Address: Send + Sync + Hash + Eq + Debug + Clone + Add<u64, Output = Address>,
    Memory: Send + Sync + Clone + MemoryADT<Address = Address, Word = [u8; WORD_LENGTH]>,
> VectorADT for IVec<WORD_LENGTH, Memory>
where
    Memory::Error: Send + Sync,
{
    type Value = Memory::Word;

    type Error = Error<Memory::Address>;

    async fn push(&mut self, values: Vec<Self::Value>) -> Result<(), Self::Error> {
        // Findex modifications are only lock-free, hence it does not guarantee a given client will
        // ever terminate.
        //
        // TODO: this loop will arguably terminate if the index is not highly contended, but we
        // need a stronger guarantee. Maybe a return with an error after reaching a certain
        // number of retries.
        let mut old = Option::<Header>::None;
        loop {
            // Generates a new header with incremented counter.
            let mut new = old.clone().unwrap_or_default();
            new.cnt += values.len() as u64;

            // Binds the correct addresses to the values.
            let mut bindings = (new.cnt - values.len() as u64..new.cnt)
                .zip(values.clone())
                .map(|(i, v)| (self.a.clone() + 1 + i, v)) // a is the header address
                .collect::<Vec<_>>();
            bindings.push((
                self.a.clone(),
                (&new).try_into().map_err(|e| Error::Conversion(e))?,
            ));

            // Attempts committing the new bindings using the old header as guard.
            let cur = self
                .m
                .guarded_write(
                    (
                        self.a.clone(),
                        old.as_ref()
                            .map(<[u8; WORD_LENGTH]>::try_from)
                            .transpose()
                            .map_err(|e| Error::Conversion(e))?,
                    ),
                    bindings,
                )
                .await
                .map_err(|e| Error::Memory(e.to_string()))?
                .map(|v| Header::try_from(v.as_slice()))
                .transpose()
                .map_err(Error::Conversion)?;

            if cur.as_ref() == old.as_ref() {
                return Ok(());
            } else {
                old = cur;
            }
        }
    }

    async fn read(&self) -> Result<Vec<Self::Value>, Self::Error> {
        // Read from a first batch of addresses:
        // - the header address;
        // - the value addresses derived from the known header.
        let old_header = Header::default();
        let addresses = std::iter::once(self.a.clone())
            .chain((0..old_header.cnt).map(|i| self.a.clone() + i + 1))
            .collect();

        let first_batch = self
            .m
            .batch_read(addresses)
            .await
            .map_err(|e| Error::Memory(e.to_string()))?;

        let second_batch = {
            let cur_header = first_batch
                .first()
                .ok_or_else(|| Error::MissingValue(self.a.clone(), 0))?
                .map(|v| Header::try_from(v.as_slice()))
                .transpose()
                .map_err(Error::Conversion)?
                .unwrap_or_default();

            if old_header.cnt < cur_header.cnt {
                // Get all missing values, if any.
                let missing_addresses = (old_header.cnt..cur_header.cnt)
                    .map(|i| self.a.clone() + i + 1)
                    .collect::<Vec<_>>();
                self.m
                    .batch_read(missing_addresses)
                    .await
                    .map_err(|e| Error::Memory(e.to_string()))?
            } else {
                vec![] // only call the memory a second time if needed
            }
        };

        first_batch
            .into_iter()
            .skip(1) // ignore the header
            .chain(second_batch)
            .enumerate()
            .map(|(i, v)| v.ok_or_else(|| Error::MissingValue(self.a.clone(), i)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_core::{CsRng, Sampling, Secret, reexport::rand_core::SeedableRng};
    use cosmian_findex_memories::{ADDRESS_LENGTH, Address, InMemory};

    use crate::{
        MemoryEncryptionLayer,
        adt::tests::{test_vector_concurrent, test_vector_sequential},
        ovec::IVec,
    };

    const WORD_LENGTH: usize = 16;

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_ovec() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();
        let address = Address::random(&mut rng);
        let obf = MemoryEncryptionLayer::new(&seed, memory.clone());
        let v = IVec::<WORD_LENGTH, _>::new(address, obf);
        test_vector_sequential(&v).await;
        memory.clear();
        test_vector_concurrent(&v).await;
    }
}
