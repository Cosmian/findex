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
    pub fn new(a: Address, m: &'a Memory) -> Self {
        Self { a, h: None, m }
    }

    pub fn push(&mut self, values: Vec<Vec<u8>>) -> Result<(), Error<Address, Memory::Error>> {
        let try_push =
            |old: Option<&Header>| -> Result<(Option<Header>, Header), Error<Address, Memory::Error>> {
                // Generates a new header which counter is incremented.
                let mut new = old.cloned().unwrap_or_default();
                new.stop += values.len() as u64;

                // Binds the correct addresses to the values.
                let mut bindings = (new.stop - values.len() as u64 ..new.stop).zip(values
                    .clone()
                    )
                    .map(|(i, v)| (self.a.clone() + 1 + i, v))
                    .collect::<Vec<_>>();
                bindings.push((self.a.clone(), (&new).into()));

                // Attempts committing the new bindings using the old header as guard.
                let cur = self
                    .m
                    .guarded_write((self.a.clone(), old.map(<Vec<u8>>::from)), bindings)?
                    .map(|v| Header::try_from(v.as_slice()))
                    .transpose()
                    .map_err(Error::Conversion)?;

                Ok((cur, new))
            };

        loop {
            let old = self.h.as_ref();
            let (cur, new) = try_push(old)?;
            if cur.as_ref() == old {
                self.h = Some(new);
                return Ok(());
            } else {
                self.h = cur;
            }
        }
    }

    pub fn read(&self) -> Result<Vec<Vec<u8>>, Error<Address, Memory::Error>> {
        // Read a first batch of addresses:
        // - the header address;
        // - the value addresses derived from the known header.
        let old_header = self.h.clone().unwrap_or_default();
        let addresses = (old_header.start + 1..old_header.stop + 1)
            .chain(0..=0)
            .map(|i| self.a.clone() + i)
            .collect();

        let mut res = self.m.batch_read(addresses)?;

        let cur_header = res
            .get(&self.a)
            .ok_or_else(|| Error::MissingValue(self.a.clone()))?
            .as_ref()
            .map(|v| Header::try_from(v.as_slice()))
            .transpose()
            .map_err(Error::Conversion)?
            .unwrap_or_default();

        let res = (cur_header.start..cur_header.stop)
            .map(|i| self.a.clone() + 1 + i)
            .map(|a| {
                let v = res.remove(&a).flatten();
                (a, v)
            })
            .collect::<Vec<_>>();

        // Read missing values if any.
        let mut missing_res = self.m.batch_read(
            res.iter()
                .filter_map(|(a, v)| if v.is_none() { Some(a) } else { None })
                .cloned()
                .collect(),
        )?;

        res.into_iter()
            .map(|(a, maybe_v)| {
                maybe_v
                    .or_else(|| missing_res.remove(&a).flatten())
                    .ok_or_else(|| Error::MissingValue(a.clone()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng, Secret};

    use crate::{address::Address, kv::KvStore, obf::EncryptionLayer, ovec::OVec, ADDRESS_LENGTH};

    #[test]
    fn test_vector_push_with_shared_cache() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::default();
        let obf = EncryptionLayer::new(seed, Arc::new(Mutex::new(rng.clone())), kv);
        let address = Address::random(&mut rng);
        let mut vector1 = OVec::new(address.clone(), &obf);
        let mut vector2 = OVec::new(address.clone(), &obf);

        let values = (0..10).map(|n| vec![n]).collect::<Vec<_>>();
        vector1.push(values[..5].to_vec()).unwrap();
        vector2.push(values[..5].to_vec()).unwrap();
        vector1.push(values[5..].to_vec()).unwrap();
        vector2.push(values[5..].to_vec()).unwrap();
        assert_eq!(
            [&values[..5], &values[..5], &values[5..], &values[5..]].concat(),
            vector1.read().unwrap()
        );
    }

    #[test]
    fn test_vector_push_without_shared_cache() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::default();
        let obf1 =
            EncryptionLayer::new(seed.clone(), Arc::new(Mutex::new(rng.clone())), kv.clone());
        let obf2 = EncryptionLayer::new(seed, Arc::new(Mutex::new(rng.clone())), kv);
        let address = Address::random(&mut rng);
        let mut vector1 = OVec::new(address.clone(), &obf1);
        let mut vector2 = OVec::new(address.clone(), &obf2);

        let values = (0..10).map(|n| vec![n]).collect::<Vec<_>>();
        vector1.push(values[..5].to_vec()).unwrap();
        // vector2 should fail its first attempt.
        vector2.push(values[..5].to_vec()).unwrap();
        vector1.push(values[5..].to_vec()).unwrap();
        // vector2 should fail its first attempt.
        vector2.push(values[5..].to_vec()).unwrap();
        assert_eq!(
            [&values[..5], &values[..5], &values[5..], &values[5..]].concat(),
            vector1.read().unwrap()
        );
    }
}
