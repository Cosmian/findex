use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::{Arc, Mutex},
};

use cosmian_crypto_core::{kdf128, CsRng, Secret};

use crate::{
    adt::VectorADT, encoding::Op, encryption_layer::MemoryEncryptionLayer, error::Error,
    ovec::IVec, Address, IndexADT, MemoryADT, ADDRESS_LENGTH, KEY_LENGTH,
};

pub struct Findex<
    const WORD_LENGTH: usize,
    Value,
    TryFromError: std::error::Error,
    Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>,
> where
    // values are serializable (but do not depend on `serde`)
    for<'z> Value: TryFrom<&'z [u8], Error = TryFromError> + AsRef<[u8]>,
    Memory::Error: Send + Sync,
{
    el: MemoryEncryptionLayer<WORD_LENGTH, Memory>,
    vectors: Mutex<
        HashMap<
            Address<ADDRESS_LENGTH>,
            IVec<WORD_LENGTH, MemoryEncryptionLayer<WORD_LENGTH, Memory>>,
        >,
    >,
    encode: Box<
        fn(
            Op,
            HashSet<Value>,
        )
            -> Result<Vec<<MemoryEncryptionLayer<WORD_LENGTH, Memory> as MemoryADT>::Word>, String>,
    >,
    decode: Box<
        fn(
            Vec<<MemoryEncryptionLayer<WORD_LENGTH, Memory> as MemoryADT>::Word>,
        ) -> Result<HashSet<Value>, TryFromError>,
    >,
}

impl<
        const WORD_LENGTH: usize,
        Value: Send + Sync + Hash + Eq,
        TryFromError: std::error::Error,
        Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>,
    > Findex<WORD_LENGTH, Value, TryFromError, Memory>
where
    for<'z> Value: TryFrom<&'z [u8], Error = TryFromError> + AsRef<[u8]>,
    Vec<u8>: From<Value>,
    Memory::Error: Send + Sync,
{
    /// Instantiates Findex with the given seed, and memory.
    pub fn new(
        seed: Secret<KEY_LENGTH>,
        rng: Arc<Mutex<CsRng>>,
        mem: Memory,
        encode: fn(Op, HashSet<Value>) -> Result<Vec<[u8; WORD_LENGTH]>, String>,
        decode: fn(Vec<[u8; WORD_LENGTH]>) -> Result<HashSet<Value>, TryFromError>,
    ) -> Self {
        // TODO: should the RNG be instantiated here?
        // Creating many instances of Findex would need more work but potentially involve less
        // waiting for the lock => bench it.
        Self {
            el: MemoryEncryptionLayer::new(seed, rng, mem),
            vectors: Mutex::new(HashMap::new()),
            encode: Box::new(encode),
            decode: Box::new(decode),
        }
    }

    /// Caches this vector for this address.
    fn bind(
        &self,
        address: Address<ADDRESS_LENGTH>,
        vector: IVec<WORD_LENGTH, MemoryEncryptionLayer<WORD_LENGTH, Memory>>,
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
    ) -> Option<IVec<WORD_LENGTH, MemoryEncryptionLayer<WORD_LENGTH, Memory>>> {
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
    async fn push<Keyword: Send + Sync + Hash + Eq + AsRef<[u8]>>(
        &self,
        op: Op,
        bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> Result<(), <Self as IndexADT<Keyword, Value>>::Error> {
        let bindings = bindings
            .map(|(kw, vals)| (self.encode)(op, vals).map(|words| (kw, words)))
            .collect::<Result<Vec<_>, String>>()
            .map_err(|e| Error::<Memory::Address, Memory::Error>::Conversion(e.to_string()))?;

        let futures = bindings
            .into_iter()
            .map(|(kw, words)| self.vector_push(kw, words))
            .collect::<Vec<_>>(); // collect for calls do be made

        for fut in futures {
            fut.await?;
        }

        Ok(())
    }

    // TODO: move this into `push` when async closures are stable.
    async fn vector_push<Keyword: Send + Sync + Hash + Eq + AsRef<[u8]>>(
        &self,
        kw: Keyword,
        values: Vec<[u8; WORD_LENGTH]>,
    ) -> Result<(), <Self as IndexADT<Keyword, Value>>::Error> {
        let a = Self::hash_address(kw.as_ref());
        let mut vector = self
            .find(&a)
            .unwrap_or_else(|| IVec::new(a.clone(), self.el.clone()));
        vector.push(values).await?;
        self.bind(a, vector);
        Ok(())
    }

    // TODO: move this into `search` when async closures are stable.
    async fn read<Keyword: Send + Sync + Hash + Eq + AsRef<[u8]>>(
        &self,
        kw: Keyword,
    ) -> Result<(Keyword, Vec<[u8; WORD_LENGTH]>), <Self as IndexADT<Keyword, Value>>::Error> {
        let a = Self::hash_address(kw.as_ref());
        let vector = self
            .find(&a)
            .unwrap_or_else(|| IVec::new(a.clone(), self.el.clone()));
        let words = vector.read().await?;
        self.bind(a, vector);
        Ok((kw, words))
    }
}

impl<
        const WORD_LENGTH: usize,
        Keyword: Send + Sync + Hash + PartialEq + Eq + AsRef<[u8]>,
        Value: Send + Sync + Hash + PartialEq + Eq,
        TryFromError: std::error::Error,
        Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = Vec<u8>>,
    > IndexADT<Keyword, Value> for Findex<WORD_LENGTH, Value, TryFromError, Memory>
where
    for<'z> Value: TryFrom<&'z [u8], Error = TryFromError> + AsRef<[u8]>,
    Vec<u8>: From<Value>,
    Memory::Error: Send + Sync,
{
    type Error = Error<
        Address<ADDRESS_LENGTH>,
        <MemoryEncryptionLayer<WORD_LENGTH, Memory> as MemoryADT>::Error,
    >;

    async fn search(
        &self,
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
        &self,
        bindings: impl Sync + Send + Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> Result<(), Self::Error> {
        self.push(Op::Insert, bindings.into_iter()).await
    }

    async fn delete(
        &self,
        bindings: impl Sync + Send + Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> Result<(), Self::Error> {
        self.push(Op::Delete, bindings.into_iter()).await
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

    use crate::{
        address::Address,
        encoding::{dummy_decode, dummy_encode},
        kv::KvStore,
        Findex, IndexADT, Value, ADDRESS_LENGTH,
    };

    const WORD_LENGTH: usize = 16;

    #[test]
    fn test_insert_search_delete_search() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let kv = KvStore::<Address<ADDRESS_LENGTH>, Vec<u8>>::default();
        let findex = Findex::new(
            seed,
            Arc::new(Mutex::new(rng)),
            kv,
            dummy_encode::<WORD_LENGTH, _>,
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
