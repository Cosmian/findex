use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::{Arc, Mutex},
};

use cosmian_crypto_core::{kdf128, CsRng, Secret};

use crate::{
    encoding::Op, error::Error, obf::MemoryEncryptionLayer, ovec::OVec, Address, Index, Stm,
    ADDRESS_LENGTH, KEY_LENGTH,
};

// Lifetime is needed to store a reference of the memory in the vectors.
pub struct Findex<
    'a,
    Value,
    TryFromError: std::error::Error,
    Memory: 'a + Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>,
> where
    Value: TryFrom<Vec<u8>, Error = TryFromError>,
    Vec<u8>: From<Value>,
{
    el: MemoryEncryptionLayer<Memory>,
    vectors: Mutex<HashMap<Address<ADDRESS_LENGTH>, OVec<'a, MemoryEncryptionLayer<Memory>>>>,
    encode: Box<fn(Op, HashSet<Value>) -> Vec<Vec<u8>>>,
    decode: Box<fn(Vec<Vec<u8>>) -> Result<HashSet<Value>, <Value as TryFrom<Vec<u8>>>::Error>>,
}

impl<
        'a,
        Value,
        TryFromError: std::error::Error,
        Memory: 'a + Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>,
    > Findex<'a, Value, TryFromError, Memory>
where
    Value: TryFrom<Vec<u8>, Error = TryFromError>,
    Vec<u8>: From<Value>,
{
    /// Instantiates Findex with the given seed, and memory.
    pub fn new(
        seed: Secret<KEY_LENGTH>,
        rng: Arc<Mutex<CsRng>>,
        stm: Memory,
        encode: fn(Op, HashSet<Value>) -> Vec<Vec<u8>>,
        decode: fn(Vec<Vec<u8>>) -> Result<HashSet<Value>, <Value as TryFrom<Vec<u8>>>::Error>,
    ) -> Self {
        // TODO: should the RNG be instantiated here?
        // Creating many instances of Findex would need more work but potentially involve less
        // waiting for the lock => bench it.
        Self {
            el: MemoryEncryptionLayer::new(seed, rng, stm),
            vectors: Mutex::new(HashMap::new()),
            encode: Box::new(encode),
            decode: Box::new(decode),
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
        TryFromError: std::error::Error,
        Memory: 'a + Stm<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>,
    > Index<'a, Keyword, Value> for Findex<'a, Value, TryFromError, Memory>
where
    Value: TryFrom<Vec<u8>, Error = TryFromError>,
    Vec<u8>: From<Value>,
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
            bindings.insert(
                kw,
                (self.decode)(vals).map_err(|e| {
                    Error::<Address<ADDRESS_LENGTH>, Memory::Error>::Conversion(e.to_string())
                })?,
            );
        }
        Ok(bindings)
    }

    async fn insert(
        &'a self,
        bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> Result<(), Self::Error> {
        self.push(bindings.map(|(kw, values)| (kw, (self.encode)(Op::Insert, values))))
            .await
    }

    async fn delete(
        &'a self,
        bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> Result<(), Self::Error> {
        self.push(bindings.map(|(kw, values)| (kw, (self.encode)(Op::Delete, values))))
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        hash::Hash,
        sync::{Arc, Mutex},
    };

    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng, Secret};
    use futures::executor::block_on;

    use crate::{
        address::Address, encoding::Op, kv::KvStore, Findex, Index, Value, ADDRESS_LENGTH,
    };

    fn dummy_encode<Value: Into<Vec<u8>>>(op: Op, vs: HashSet<Value>) -> Vec<Vec<u8>> {
        vs.into_iter()
            .map(Into::into)
            .map(|bytes| {
                if op == Op::Insert {
                    [vec![1], bytes].concat()
                } else {
                    [vec![0], bytes].concat()
                }
            })
            .collect()
    }

    fn dummy_decode<
        TryFromError: std::error::Error,
        Value: Hash + PartialEq + Eq + TryFrom<Vec<u8>, Error = TryFromError>,
    >(
        ws: Vec<Vec<u8>>,
    ) -> Result<HashSet<Value>, <Value as TryFrom<Vec<u8>>>::Error> {
        let mut res = HashSet::with_capacity(ws.len());
        for w in ws {
            if !w.is_empty() {
                let v = Value::try_from(w[1..].to_vec())?;
                if w[0] == 1 {
                    res.insert(v);
                } else {
                    res.remove(&v);
                }
            }
        }
        Ok(res)
    }

    #[test]
    fn test_insert_search_delete_search() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::default();
        let findex = Findex::new(
            seed,
            Arc::new(Mutex::new(rng)),
            kv,
            dummy_encode,
            dummy_decode,
        );
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

        block_on(findex.delete(bindings.clone().into_iter())).unwrap();
        let res = block_on(findex.search(bindings.keys().cloned())).unwrap();
        assert_eq!(
            HashMap::from_iter([("cat", HashSet::new()), ("dog", HashSet::new())]),
            res
        );
    }
}
