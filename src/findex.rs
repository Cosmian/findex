use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::{Arc, Mutex},
};

use cosmian_crypto_core::{kdf128, CsRng, Secret};

use crate::{
    error::Error, obf::EncryptionLayer, ovec::OVec, Address, Index, Stm, ADDRESS_LENGTH, KEY_LENGTH,
};

pub struct Findex<'a, Memory: 'a + Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>> {
    el: EncryptionLayer<Memory>,
    vectors: Mutex<HashMap<Address<ADDRESS_LENGTH>, OVec<'a, EncryptionLayer<Memory>>>>,
}

impl<'a, Memory: 'a + Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>> Findex<'a, Memory> {
    pub fn new(seed: Secret<KEY_LENGTH>, rng: Arc<Mutex<CsRng>>, stm: Memory) -> Self {
        Self {
            el: EncryptionLayer::new(seed, rng, stm),
            vectors: Mutex::new(HashMap::new()),
        }
    }
}

impl<
        'a,
        Keyword: Hash + PartialEq + Eq + AsRef<[u8]>,
        Value: Hash + PartialEq + Eq + From<Vec<u8>>,
        Memory: 'a + Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>,
    > Index<'a, Keyword, Value> for Findex<'a, Memory>
where
    for<'z> Vec<u8>: From<&'z Value>,
{
    type Error = Error<Address<ADDRESS_LENGTH>, <EncryptionLayer<Memory> as Stm>::Error>;

    fn search(
        &'a self,
        keywords: impl Iterator<Item = Keyword>,
    ) -> Result<HashMap<Keyword, HashSet<Value>>, Self::Error> {
        keywords
            .map(|kw| {
                let mut a = Address::<ADDRESS_LENGTH>::default();
                kdf128!(&mut a, kw.as_ref());
                let mut vectors = self.vectors.lock().expect("poisoned mutex");
                let vector = vectors
                    .entry(a.clone())
                    .or_insert_with(|| OVec::<'a, EncryptionLayer<Memory>>::new(a, &self.el));
                let links = vector.read()?;
                Ok((
                    kw,
                    links.into_iter().map(Value::from).collect::<HashSet<_>>(),
                ))
            })
            .collect()
    }

    fn insert(
        &'a self,
        bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> Result<(), Self::Error> {
        bindings
            .map(|(kw, vals)| {
                let mut a = Address::<ADDRESS_LENGTH>::default();
                kdf128!(&mut a, kw.as_ref());
                let mut vectors = self.vectors.lock().expect("poisoned mutex");
                let vector = vectors
                    .entry(a.clone())
                    .or_insert_with(|| OVec::<'a, EncryptionLayer<Memory>>::new(a, &self.el));
                vector.push(vals.iter().map(<Vec<u8>>::from).collect::<Vec<_>>())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }

    fn delete(
        _bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        sync::{Arc, Mutex},
    };

    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng, Secret};

    use crate::{address::Address, kv::KvStore, Findex, Index, Value, ADDRESS_LENGTH};

    #[test]
    fn test_insert_search() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::default();
        let findex = Findex::new(seed, Arc::new(Mutex::new(rng)), kv);
        let bindings = HashMap::<&str, HashSet<Value>>::from_iter([
            (
                "cat",
                HashSet::from_iter([Value::from(1), Value::from(3), Value::from(5)]),
            ),
            (
                "dog",
                HashSet::from_iter([Value::from(0), Value::from(2), Value::from(4)]),
            ),
        ]);
        findex.insert(bindings.clone().into_iter()).unwrap();
        let res = findex.search(bindings.keys().cloned()).unwrap();
        assert_eq!(bindings, res);
    }
}
