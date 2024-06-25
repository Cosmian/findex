use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::{Arc, Mutex},
};

use cosmian_crypto_core::{kdf128, CsRng, Secret};

use crate::{
    error::Error, obf::MemoryEncryptionLayer, ovec::OVec, Address, Index, Stm, ADDRESS_LENGTH,
    KEY_LENGTH,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Insert,
    Delete,
}

pub struct Findex<'a, Memory: 'a + Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>> {
    el: MemoryEncryptionLayer<Memory>,
    vectors: Mutex<HashMap<Address<ADDRESS_LENGTH>, OVec<'a, MemoryEncryptionLayer<Memory>>>>,
}

impl<'a, Memory: 'a + Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>> Findex<'a, Memory> {
    /// Instantiates Findex with the given seed, and memory.
    pub fn new(seed: Secret<KEY_LENGTH>, rng: Arc<Mutex<CsRng>>, stm: Memory) -> Self {
        // TODO: should the RNG be instantiated here?
        // Creating many instances of Findex would need more work but potentially involve less
        // waiting for the lock => bench it.
        Self {
            el: MemoryEncryptionLayer::new(seed, rng, stm),
            vectors: Mutex::new(HashMap::new()),
        }
    }

    /// Caches this vector for this address.
    fn bind(
        &'a self,
        address: Address<ADDRESS_LENGTH>,
        vector: OVec<'a, MemoryEncryptionLayer<Memory>>,
    ) {
        self.vectors
            .lock()
            .expect("poisoned mutex")
            .insert(address, vector);
    }

    /// Retrieves the vector cached for this address, if any.
    fn find(
        &self,
        address: &Address<ADDRESS_LENGTH>,
    ) -> Option<OVec<MemoryEncryptionLayer<Memory>>> {
        self.vectors
            .lock()
            .expect("poisoned mutex")
            .get(address)
            .cloned()
    }

    fn hash_address(bytes: &[u8]) -> Address<ADDRESS_LENGTH> {
        let mut a = Address::<ADDRESS_LENGTH>::default();
        kdf128!(&mut a, bytes);
        a
    }

    fn decompose<Value>(_op: Op, values: impl Iterator<Item = Value>) -> Vec<Vec<u8>>
    where
        for<'z> Vec<u8>: From<&'z Value>,
    {
        values.map(|v| <Vec<u8>>::from(&v)).collect()
    }

    fn recompose<Value: Hash + PartialEq + Eq + From<Vec<u8>>>(
        words: Vec<Vec<u8>>,
    ) -> HashSet<Value> {
        words.into_iter().map(Value::from).collect()
    }

    /// Pushes the given bindings to the vectors associated to the bound keyword.
    ///
    /// All vector push operations are performed in parallel (via async calls), not batched.
    async fn push<Keyword: AsRef<[u8]>>(
        &'a self,
        bindings: impl Iterator<Item = (Keyword, Vec<Vec<u8>>)>,
    ) -> Result<(), Error<Address<ADDRESS_LENGTH>, <MemoryEncryptionLayer<Memory> as Stm>::Error>>
    {
        let futures = bindings
            .map(|(kw, vals)| self.vector_push(kw, vals))
            .collect::<Vec<_>>(); // collect for calls do be made

        for fut in futures {
            fut.await?;
        }

        Ok(())
    }

    // TODO: move into push as an async closure when stable.
    async fn vector_push<Keyword: AsRef<[u8]>>(
        &'a self,
        kw: Keyword,
        values: Vec<Vec<u8>>,
    ) -> Result<(), Error<Address<ADDRESS_LENGTH>, <MemoryEncryptionLayer<Memory> as Stm>::Error>>
    {
        let a = Self::hash_address(kw.as_ref());
        let mut vector = self
            .find(&a)
            .unwrap_or_else(|| OVec::new(a.clone(), &self.el));
        vector.push(values).await?;
        self.bind(a, vector);
        Ok(())
    }

    // TODO: move into search as an async closure when stable.
    async fn read<Keyword: AsRef<[u8]>>(
        &'a self,
        kw: Keyword,
    ) -> Result<
        (Keyword, Vec<Vec<u8>>),
        Error<Address<ADDRESS_LENGTH>, <MemoryEncryptionLayer<Memory> as Stm>::Error>,
    > {
        let a = Self::hash_address(kw.as_ref());
        let vector = self
            .find(&a)
            .unwrap_or_else(|| OVec::new(a.clone(), &self.el));
        let words = vector.read().await?;
        self.bind(a, vector);
        Ok((kw, words))
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
    type Error = Error<Address<ADDRESS_LENGTH>, <MemoryEncryptionLayer<Memory> as Stm>::Error>;

    async fn search(
        &'a self,
        keywords: impl Iterator<Item = Keyword>,
    ) -> Result<HashMap<Keyword, HashSet<Value>>, Self::Error> {
        let futures = keywords
            .map(|kw| self.read::<Keyword>(kw))
            .collect::<Vec<_>>();
        let mut bindings = HashMap::new();
        for fut in futures {
            let (kw, vals) = fut.await?;
            bindings.insert(kw, Self::recompose(vals));
        }
        Ok(bindings)
    }

    async fn insert(
        &'a self,
        bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> Result<(), Self::Error> {
        self.push(
            bindings.map(|(kw, values)| (kw, Self::decompose(Op::Insert, values.into_iter()))),
        )
        .await
    }

    async fn delete(
        &'a self,
        bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> Result<(), Self::Error> {
        self.push(
            bindings.map(|(kw, values)| (kw, Self::decompose(Op::Delete, values.into_iter()))),
        )
        .await
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
