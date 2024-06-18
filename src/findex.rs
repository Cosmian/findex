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

    fn set_vector(
        &'a self,
        address: Address<ADDRESS_LENGTH>,
        vector: OVec<'a, EncryptionLayer<Memory>>,
    ) {
        self.vectors
            .lock()
            .expect("poisoned mutex")
            .insert(address, vector);
    }

    fn get_vector(
        &'a self,
        address: &Address<ADDRESS_LENGTH>,
    ) -> OVec<'a, EncryptionLayer<Memory>> {
        self.vectors
            .lock()
            .expect("poisoned mutex")
            .get(address)
            .cloned()
            .unwrap_or_else(|| OVec::<'a, EncryptionLayer<Memory>>::new(address.clone(), &self.el))
    }

    fn hash_address(bytes: &[u8]) -> Address<ADDRESS_LENGTH> {
        let mut a = Address::<ADDRESS_LENGTH>::default();
        kdf128!(&mut a, bytes);
        a
    }

    fn decompose<Value>(values: impl Iterator<Item = Value>) -> Vec<Vec<u8>>
    where
        for<'z> Vec<u8>: From<&'z Value>,
    {
        values.map(|v| <Vec<u8>>::from(&v)).collect()
    }

    fn recompose<Value>(links: Vec<Vec<u8>>) -> HashSet<Value>
    where
        Value: Hash + PartialEq + Eq + From<Vec<u8>>,
    {
        links.into_iter().map(Value::from).collect()
    }

    async fn vector_push<Keyword: AsRef<[u8]>, Value>(
        &'a self,
        kw: Keyword,
        values: HashSet<Value>,
    ) -> Result<(), Error<Address<ADDRESS_LENGTH>, <EncryptionLayer<Memory> as Stm>::Error>>
    where
        for<'z> Vec<u8>: From<&'z Value>,
    {
        let a = Self::hash_address(kw.as_ref());
        let mut vector = self.get_vector(&a);
        vector.push(Self::decompose(values.into_iter())).await?;
        self.set_vector(a, vector);
        Ok(())
    }

    async fn read<Keyword: AsRef<[u8]>, Value: Hash + PartialEq + Eq + From<Vec<u8>>>(
        &'a self,
        kw: Keyword,
    ) -> Result<
        (Keyword, HashSet<Value>),
        Error<Address<ADDRESS_LENGTH>, <EncryptionLayer<Memory> as Stm>::Error>,
    > {
        let a = Self::hash_address(kw.as_ref());
        let vector = self.get_vector(&a);
        let links = vector.read().await?;
        self.set_vector(a, vector);
        Ok((kw, Self::recompose(links)))
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

    async fn search(
        &'a self,
        keywords: impl Iterator<Item = Keyword>,
    ) -> Result<HashMap<Keyword, HashSet<Value>>, Self::Error> {
        let futures = keywords
            .map(|kw| self.read::<Keyword, Value>(kw))
            .collect::<Vec<_>>();
        let mut bindings = HashMap::new();
        for fut in futures {
            let (kw, vals) = fut.await?;
            bindings.insert(kw, vals);
        }
        Ok(bindings)
    }

    async fn insert(
        &'a self,
        bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> Result<(), Self::Error> {
        let futures = bindings
            .map(|(kw, vals)| self.vector_push(kw, vals))
            .collect::<Vec<_>>();
        for fut in futures {
            fut.await?;
        }
        Ok(())
    }

    async fn delete(
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
    use futures::executor::block_on;

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
        block_on(findex.insert(bindings.clone().into_iter())).unwrap();
        let res = block_on(findex.search(bindings.keys().cloned())).unwrap();
        assert_eq!(bindings, res);
    }
}
