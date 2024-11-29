use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::{Arc, Mutex},
};

use tiny_keccak::{Hasher, Sha3};

use crate::{
    ADDRESS_LENGTH, Address, IndexADT, KEY_LENGTH, MemoryADT, adt::VectorADT, encoding::Op,
    encryption_layer::MemoryEncryptionLayer, error::Error, ovec::IVec, secret::Secret,
};

#[derive(Clone, Debug)]
pub struct Findex<
    const WORD_LENGTH: usize,
    Value,
    TryFromError: std::error::Error,
    Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> where
    // values are serializable (but do not depend on `serde`)
    for<'z> Value: TryFrom<&'z [u8], Error = TryFromError> + AsRef<[u8]>,
    Memory::Error: Send + Sync,
{
    el: MemoryEncryptionLayer<WORD_LENGTH, Memory>,
    cache: Arc<
        Mutex<
            HashMap<
                Address<ADDRESS_LENGTH>,
                IVec<WORD_LENGTH, MemoryEncryptionLayer<WORD_LENGTH, Memory>>,
            >,
        >,
    >,
    encode: Arc<
        fn(
            Op,
            HashSet<Value>,
        )
            -> Result<Vec<<MemoryEncryptionLayer<WORD_LENGTH, Memory> as MemoryADT>::Word>, String>,
    >,
    decode: Arc<
        fn(
            Vec<<MemoryEncryptionLayer<WORD_LENGTH, Memory> as MemoryADT>::Word>,
        ) -> Result<HashSet<Value>, TryFromError>,
    >,
}

impl<
    const WORD_LENGTH: usize,
    Value: Send + Sync + Hash + Eq,
    TryFromError: std::error::Error,
    Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> Findex<WORD_LENGTH, Value, TryFromError, Memory>
where
    for<'z> Value: TryFrom<&'z [u8], Error = TryFromError> + AsRef<[u8]>,
    Vec<u8>: From<Value>,
    Memory::Error: Send + Sync,
{
    /// Instantiates Findex with the given seed, and memory.
    pub fn new(
        seed: Secret<KEY_LENGTH>,
        mem: Memory,
        encode: fn(Op, HashSet<Value>) -> Result<Vec<[u8; WORD_LENGTH]>, String>,
        decode: fn(Vec<[u8; WORD_LENGTH]>) -> Result<HashSet<Value>, TryFromError>,
    ) -> Self {
        Self {
            el: MemoryEncryptionLayer::new(seed, mem),
            cache: Arc::new(Mutex::new(HashMap::new())),
            encode: Arc::new(encode),
            decode: Arc::new(decode),
        }
    }

    pub fn clear(&self) {
        self.cache.lock().unwrap().clear();
    }

    /// Caches this vector for this address.
    fn bind(
        &self,
        address: Address<ADDRESS_LENGTH>,
        vector: IVec<WORD_LENGTH, MemoryEncryptionLayer<WORD_LENGTH, Memory>>,
    ) {
        self.cache
            .lock()
            .expect("poisoned mutex")
            .insert(address, vector);
    }

    /// Retrieves the vector cached for this address, if any.
    fn find(
        &self,
        address: &Address<ADDRESS_LENGTH>,
    ) -> Option<IVec<WORD_LENGTH, MemoryEncryptionLayer<WORD_LENGTH, Memory>>> {
        self.cache
            .lock()
            .expect("poisoned mutex")
            .get(address)
            .cloned()
    }

    fn hash_address(bytes: &[u8]) -> Address<ADDRESS_LENGTH> {
        let mut a = Address::<ADDRESS_LENGTH>::default();
        let mut hash = Sha3::v256();
        hash.update(bytes);
        hash.finalize(&mut *a);
        a
    }

    /// Pushes the given bindings to the vectors associated to the bound
    /// keyword.
    ///
    /// All vector push operations are performed in parallel (via async calls),
    /// not batched.
    async fn push<Keyword: Send + Sync + Hash + Eq + AsRef<[u8]>>(
        &self,
        op: Op,
        bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> Result<(), <Self as IndexADT<Keyword, Value>>::Error> {
        let bindings = bindings
            .map(|(kw, vals)| (self.encode)(op, vals).map(|words| (kw, words)))
            .collect::<Result<Vec<_>, String>>()
            .map_err(|e| Error::<_, Memory::Error>::Conversion(e.to_string()))?;

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
        let mut ivec = self
            .find(&a)
            .unwrap_or_else(|| IVec::new(a.clone(), self.el.clone()));
        ivec.push(values).await?;
        self.bind(a, ivec);
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
    Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
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
        let mut bindings = HashMap::with_capacity(futures.len());
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
        self.push(Op::Insert, bindings).await
    }

    async fn delete(
        &self,
        bindings: impl Sync + Send + Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> Result<(), Self::Error> {
        self.push(Op::Delete, bindings).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use futures::executor::block_on;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use crate::{
        ADDRESS_LENGTH, Findex, IndexADT, Value,
        address::Address,
        encoding::{dummy_decode, dummy_encode},
        memory::in_memory_store::InMemory,
        secret::Secret,
    };

    const WORD_LENGTH: usize = 16;

    #[test]
    fn test_insert_search_delete_search() {
        let mut rng = ChaChaRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();
        let findex = Findex::new(seed, memory, dummy_encode::<WORD_LENGTH, _>, dummy_decode);
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

    #[cfg(feature = "redis-store")]
    fn get_redis_url() -> String {
        if let Ok(var_env) = std::env::var("REDIS_HOST") {
            format!("redis://{var_env}:6379")
        } else {
            "redis://localhost:6379".to_string()
        }
    }

    #[tokio::test]
    #[cfg(feature = "redis-store")]
    async fn test_redis_insert_search_delete_search() {
        use crate::RedisStore;

        let mut rng = ChaChaRng::from_entropy();
        let seed = Secret::random(&mut rng);
        const TEST_ADR_WORD_LENGTH: usize = 16;
        let memory = RedisStore::<Address<TEST_ADR_WORD_LENGTH>, TEST_ADR_WORD_LENGTH>::connect(
            &get_redis_url(),
        )
        .await
        .unwrap();
        let findex = Findex::new(seed, memory, dummy_encode::<WORD_LENGTH, _>, dummy_decode);
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
        findex.insert(bindings.clone().into_iter()).await.unwrap(); // using block_on here causes a never ending execution
        let res = findex.search(bindings.keys().cloned()).await.unwrap();
        assert_eq!(bindings, res);

        findex.delete(bindings.clone().into_iter()).await.unwrap();
        let res = findex.search(bindings.keys().cloned()).await.unwrap();
        assert_eq!(
            HashMap::from_iter([("cat", HashSet::new()), ("dog", HashSet::new())]),
            res
        );
    }
}
