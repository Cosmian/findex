use std::{fmt::Debug, hash::Hash, ops::Add};

use crate::{error::Error, Stm};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Header {
    pub(crate) start: u64,
    pub(crate) stop: u64,
}

impl From<&Header> for Vec<u8> {
    fn from(header: &Header) -> Self {
        let stop = header.stop.to_be_bytes();
        let start = header.start.to_be_bytes();
        [start, stop].concat()
    }
}

impl From<Header> for Vec<u8> {
    fn from(value: Header) -> Self {
        Self::from(&value)
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = String;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 16 {
            return Err(format!(
                "value to short to be converted to header: need {}, got {}",
                16,
                value.len()
            ));
        }
        let start = <[u8; 8]>::try_from(&value[..8]).expect("length is correct");
        let stop = <[u8; 8]>::try_from(&value[8..]).expect("length is correct");
        Ok(Self {
            start: u64::from_be_bytes(start),
            stop: u64::from_be_bytes(stop),
        })
    }
}

/// A client-side implementation of a vector.
///
/// ```txt
///     +------------distant-memory-----------+
///     |                                     |
/// a --|--> | header (h) | v_1 | ... | v_n | |
///     |                                     |
///     +------------distant-memory-----------+
/// ```
#[derive(Debug)]
pub struct OVec<'a, Memory: Stm<Word = Vec<u8>>> {
    a: Memory::Address,
    h: Option<Header>,
    m: &'a Memory,
}

impl<'a, Address: Clone, Memory: Stm<Address = Address, Word = Vec<u8>>> Clone
    for OVec<'a, Memory>
{
    fn clone(&self) -> Self {
        Self {
            a: self.a.clone(),
            h: self.h.clone(),
            m: self.m,
        }
    }
}

impl<
        'a,
        Address: Hash + Eq + Debug + Clone + Add<u64, Output = Address>,
        Memory: Stm<Address = Address, Word = Vec<u8>>,
    > OVec<'a, Memory>
{
    /// (Lazily) instantiates a new vector at this address in this memory: no value is written
    /// before the first push.
    pub fn new(a: Address, m: &'a Memory) -> Self {
        Self { a, h: None, m }
    }

    /// Atomically pushes the given values at the end of this vector. Retries upon conflict.
    pub async fn push(
        &mut self,
        values: Vec<Vec<u8>>,
    ) -> Result<(), Error<Address, Memory::Error>> {
        loop {
            let old = self.h.as_ref();
            let (cur, new) = {
                // Generates a new header which counter is incremented.
                let mut new = old.cloned().unwrap_or_default();
                new.stop += values.len() as u64;

                // Binds the correct addresses to the values.
                let mut bindings = (new.stop - values.len() as u64..new.stop)
                    .zip(values.clone())
                    .map(|(i, v)| (self.a.clone() + 1 + i, v))
                    .collect::<Vec<_>>();
                bindings.push((self.a.clone(), (&new).into()));

                // Attempts committing the new bindings using the old header as guard.
                let cur = self
                    .m
                    .guarded_write((self.a.clone(), old.map(<Vec<u8>>::from)), bindings)
                    .await?
                    .map(|v| Header::try_from(v.as_slice()))
                    .transpose()
                    .map_err(Error::Conversion)?;

                (cur, new)
            };
            if cur.as_ref() == old {
                self.h = Some(new);
                return Ok(());
            } else {
                self.h = cur;
                // Findex modifications are only lock-free, hence it does not guarantee a given
                // client will ever terminate.
                //
                // TODO: this loop will arguably terminate if the index is not highly contended,
                // but we need a stronger guarantee. Maybe a return with an error after a reaching
                // a certain number of retries.
            }
        }
    }

    /// Atomically reads the values stored in this vector.
    pub async fn read(&self) -> Result<Vec<Vec<u8>>, Error<Address, Memory::Error>> {
        // Read from a first batch of addresses:
        // - the header address;
        // - the value addresses derived from the known header.
        let old_header = self.h.clone().unwrap_or_default();
        let addresses = [self.a.clone()]
            .into_iter()
            .chain((old_header.start..old_header.stop).map(|i| self.a.clone() + i + 1))
            .collect();

        let res = self.m.batch_read(addresses).await?;

        let cur_header = res[0]
            .clone()
            .map(|v| {
                println!("{v:?}");
                Header::try_from(v.as_slice())
            })
            .transpose()
            .map_err(Error::Conversion)?
            .unwrap_or_default();

        // Get all missing values, if any.
        let missing_addresses = (cur_header.start.max(old_header.stop)..cur_header.stop)
            .map(|i| self.a.clone() + i + 1)
            .collect::<Vec<_>>();

        let missing_values = if missing_addresses.is_empty() {
            vec![] // only call the memory a second time if needed
        } else {
            self.m.batch_read(missing_addresses).await?
        };

        res.into_iter()
            .skip(1)
            .chain(missing_values)
            .enumerate()
            .map(|(i, v)| v.ok_or_else(|| Error::MissingValue(self.a.clone() + i as u64)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;
    use std::sync::{Arc, Mutex};

    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng, Secret};

    use crate::{
        address::Address, kv::KvStore, obf::MemoryEncryptionLayer, ovec::OVec, ADDRESS_LENGTH,
    };

    #[test]
    fn test_vector_push_with_shared_cache() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::default();
        let obf = MemoryEncryptionLayer::new(seed, Arc::new(Mutex::new(rng.clone())), kv);
        let address = Address::random(&mut rng);
        let mut vector1 = OVec::new(address.clone(), &obf);
        let mut vector2 = OVec::new(address.clone(), &obf);

        let values = (0..10).map(|n| vec![n]).collect::<Vec<_>>();
        block_on(vector1.push(values[..5].to_vec())).unwrap();
        block_on(vector2.push(values[..5].to_vec())).unwrap();
        block_on(vector1.push(values[5..].to_vec())).unwrap();
        block_on(vector2.push(values[5..].to_vec())).unwrap();
        assert_eq!(
            [&values[..5], &values[..5], &values[5..], &values[5..]].concat(),
            block_on(vector1.read()).unwrap()
        );
    }

    #[test]
    fn test_vector_push_without_shared_cache() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::default();
        let obf1 =
            MemoryEncryptionLayer::new(seed.clone(), Arc::new(Mutex::new(rng.clone())), kv.clone());
        let obf2 = MemoryEncryptionLayer::new(seed, Arc::new(Mutex::new(rng.clone())), kv);
        let address = Address::random(&mut rng);
        let mut vector1 = OVec::new(address.clone(), &obf1);
        let mut vector2 = OVec::new(address.clone(), &obf2);

        let values = (0..10).map(|n| vec![n]).collect::<Vec<_>>();
        block_on(vector1.push(values[..5].to_vec())).unwrap();
        // vector2 should fail its first attempt.
        block_on(vector2.push(values[..5].to_vec())).unwrap();
        block_on(vector1.push(values[5..].to_vec())).unwrap();
        // vector2 should fail its first attempt.
        block_on(vector2.push(values[5..].to_vec())).unwrap();
        assert_eq!(
            [&values[..5], &values[..5], &values[5..], &values[5..]].concat(),
            block_on(vector1.read()).unwrap()
        );
    }
}
