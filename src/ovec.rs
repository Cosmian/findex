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
#[derive(Debug, Clone)]
pub struct OVec<'a, Memory: Stm<Word = Vec<u8>>> {
    a: Memory::Address,
    h: Option<Header>,
    m: &'a Memory,
}

impl<
        'a,
        Address: Hash + Eq + Debug + Clone + Add<u64, Output = Address>,
        Memory: Stm<Address = Address, Word = Vec<u8>>,
    > OVec<'a, Memory>
{
    pub fn push(&mut self, values: Vec<Vec<u8>>) -> Result<(), Error<Address, Memory::Error>> {
        let try_push =
            |old: Option<&Header>| -> Result<(Option<Header>, Header), Error<Address, Memory::Error>> {
                // Generates a new header which counter is incremented.
                let mut new = old.cloned().unwrap_or_default();
                new.stop += values.len() as u64;

                // Binds the correct addresses to the values.
                let mut bindings = values
                    .iter()
                    .cloned()
                    .enumerate()
                    .map(|(i, v)| (self.a.clone() + new.start + 1 + i as u64, v))
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
        let header = self.h.clone().unwrap_or_default();
        let addresses = (header.start + 1..header.stop + 1)
            .chain(0..=0)
            .map(|i| self.a.clone() + i)
            .collect();

        let mut res = self.m.batch_read(addresses)?;

        let current_header = res
            .get(&self.a)
            .ok_or_else(|| Error::MissingValue(self.a.clone()))?
            .as_ref()
            .map(|v| Header::try_from(v.as_slice()))
            .transpose()
            .map_err(Error::Conversion)?
            .unwrap_or_default();

        let res = (current_header.start..current_header.stop)
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

//#[cfg(test)]
//mod tests {
///// Ensures a transaction can express an vector push operation:
///// - the counter is correctly incremented and all values are written;
///// - using the wrong value in the guard fails the operation and returns the current value.
//fn test_vector_push() {
//let mut rng = CsRng::from_entropy();
//let seed = Secret::random(&mut rng);
//let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::new();
//let obf = ObfuscationLayer::new(seed, rng.clone(), kv);
//let ovec = OVec::new(seed, rng.clone(), obf);

//let header_addr = Address::<ADDRESS_LENGTH>::random(&mut rng);

//let val_addr_1 = Address::<ADDRESS_LENGTH>::random(&mut rng);
//let val_addr_2 = Address::<ADDRESS_LENGTH>::random(&mut rng);
//let val_addr_3 = Address::<ADDRESS_LENGTH>::random(&mut rng);
//let val_addr_4 = Address::<ADDRESS_LENGTH>::random(&mut rng);

//assert_eq!(
//obf.guarded_write(
//(header_addr.clone(), None),
//vec![
//(header_addr.clone(), vec![2]),
//(val_addr_1.clone(), vec![1]),
//(val_addr_2.clone(), vec![1])
//]
//)
//.unwrap(),
//None
//);

//assert_eq!(
//obf.guarded_write(
//(header_addr.clone(), None),
//vec![
//(header_addr.clone(), vec![2]),
//(val_addr_1.clone(), vec![3]),
//(val_addr_2.clone(), vec![3])
//]
//)
//.unwrap(),
//Some(vec![2])
//);

//assert_eq!(
//obf.guarded_write(
//(header_addr.clone(), Some(vec![2])),
//vec![
//(header_addr.clone(), vec![4]),
//(val_addr_3.clone(), vec![2]),
//(val_addr_4.clone(), vec![2])
//]
//)
//.unwrap(),
//Some(vec![2])
//);

//assert_eq!(
//HashSet::<(Address<ADDRESS_LENGTH>, Option<Vec<u8>>)>::from_iter([
//(header_addr.clone(), Some(vec![4])),
//(val_addr_1.clone(), Some(vec![1])),
//(val_addr_2.clone(), Some(vec![1])),
//(val_addr_3.clone(), Some(vec![2])),
//(val_addr_4.clone(), Some(vec![2]))
//]),
//HashSet::from_iter(
//obf.batch_read(vec![
//header_addr,
//val_addr_1,
//val_addr_2,
//val_addr_3,
//val_addr_4
//])
//.unwrap()
//),
//)
//}
//}
