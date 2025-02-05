#![allow(clippy::type_complexity)]

use std::{
    collections::HashSet,
    fmt::Debug,
    hash::{DefaultHasher, Hash, Hasher},
    sync::Arc,
};

use crate::{
    ADDRESS_LENGTH, Address, IndexADT, MemoryADT,
    adt::VectorADT,
    encoding::{Decoder, Encoder},
    error::Error,
    ovec::IVec,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Insert,
    Delete,
}

#[derive(Clone, Debug)]
pub struct Findex<
    const WORD_LENGTH: usize,
    Value: Send + Sync + Hash + Eq,
    EncodingError: Send + Sync + Debug,
    Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> {
    el: Memory,
    encode: Arc<Encoder<Value, Memory::Word, EncodingError>>,
    decode: Arc<Decoder<Value, Memory::Word, EncodingError>>,
}

impl<
    const WORD_LENGTH: usize,
    Value: Send + Sync + Hash + Eq,
    EncodingError: Send + Sync + Debug,
    Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> Findex<WORD_LENGTH, Value, EncodingError, Memory>
{
    /// Instantiates Findex with the given seed, and memory.
    pub fn new(
        memory: Memory,
        encode: Encoder<Value, Memory::Word, EncodingError>,
        decode: Decoder<Value, Memory::Word, EncodingError>,
    ) -> Self {
        Self {
            el: memory,
            encode: Arc::new(encode),
            decode: Arc::new(decode),
        }
    }

    fn hash_keyword<Keyword: Hash>(kw: &Keyword) -> Address<ADDRESS_LENGTH> {
        let h = |n: u8| {
            let mut hasher = DefaultHasher::default();
            kw.hash(&mut hasher);
            n.hash(&mut hasher);
            hasher.finish()
        };

        // Hash the keyword twice to get enough collision resistance.
        let mut a = Address::<ADDRESS_LENGTH>::default();
        a[..8].copy_from_slice(&h(1).to_be_bytes());
        a[8..].copy_from_slice(&h(2).to_be_bytes());
        a
    }

    /// Pushes the given bindings to the vectors associated to the bound keyword.
    ///
    /// All vector push operations are performed in parallel (via async calls), not batched.
    async fn push<Keyword: Send + Sync + Hash + Eq>(
        &self,
        op: Op,
        kw: Keyword,
        vs: HashSet<Value>,
    ) -> Result<(), <Self as IndexADT<Keyword, Value>>::Error> {
        let words = (self.encode)(op, vs).map_err(|e| Error::Conversion(format!("{e:?}")))?;
        let l = Self::hash_keyword(&kw);
        IVec::new(l, self.el.clone()).push(words).await
    }
}

impl<
    const WORD_LENGTH: usize,
    Keyword: Send + Sync + Hash + Eq,
    Value: Send + Sync + Hash + Eq,
    EncodingError: Send + Sync + Debug,
    Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> IndexADT<Keyword, Value> for Findex<WORD_LENGTH, Value, EncodingError, Memory>
{
    type Error = Error<Address<ADDRESS_LENGTH>>;

    async fn search(&self, kw: &Keyword) -> Result<HashSet<Value>, Self::Error> {
        let l = Self::hash_keyword(kw);
        let words = IVec::new(l, self.el.clone()).read().await?;
        (self.decode)(words).map_err(|e| Error::Conversion(format!("{e:?}")))
    }

    async fn insert(
        &self,
        kw: Keyword,
        vs: impl Sync + Send + IntoIterator<Item = Value>,
    ) -> Result<(), Self::Error> {
        self.push(Op::Insert, kw, vs.into_iter().collect()).await
    }

    async fn delete(
        &self,
        kw: Keyword,
        vs: impl Sync + Send + IntoIterator<Item = Value>,
    ) -> Result<(), Self::Error> {
        self.push(Op::Delete, kw, vs.into_iter().collect()).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use futures::executor::block_on;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use crate::{
        ADDRESS_LENGTH, Findex, InMemory, IndexADT, Value, address::Address, dummy_decode,
        dummy_encode, memory::MemoryEncryptionLayer, secret::Secret,
    };

    const WORD_LENGTH: usize = 16;

    #[test]
    fn test_insert_search_delete_search() {
        let mut rng = ChaChaRng::from_os_rng();
        let seed = Secret::random(&mut rng);
        let memory = MemoryEncryptionLayer::new(
            &seed,
            InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default(),
        );
        let findex = Findex::new(memory, dummy_encode::<WORD_LENGTH, _>, dummy_decode);
        let cat_bindings = [Value::from(1), Value::from(3), Value::from(5)];
        let dog_bindings = [Value::from(0), Value::from(2), Value::from(4)];
        block_on(findex.insert("cat".to_string(), cat_bindings.clone())).unwrap();
        block_on(findex.insert("dog".to_string(), dog_bindings.clone())).unwrap();
        let cat_res = block_on(findex.search(&"cat".to_string())).unwrap();
        let dog_res = block_on(findex.search(&"dog".to_string())).unwrap();
        assert_eq!(
            cat_bindings.iter().cloned().collect::<HashSet<_>>(),
            cat_res
        );
        assert_eq!(
            dog_bindings.iter().cloned().collect::<HashSet<_>>(),
            dog_res
        );

        block_on(findex.delete("dog", dog_bindings)).unwrap();
        block_on(findex.delete("cat", cat_bindings)).unwrap();
        let cat_res = block_on(findex.search(&"cat".to_string())).unwrap();
        let dog_res = block_on(findex.search(&"dog".to_string())).unwrap();
        assert_eq!(HashSet::new(), cat_res);
        assert_eq!(HashSet::new(), dog_res);
    }
}
