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

#[derive(Debug)]
pub struct Findex<
    const WORD_LENGTH: usize,
    Value: Send + Sync + Hash + Eq,
    EncodingError: Send + Sync + Debug,
    Memory: Send + Sync + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
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
> Clone for Findex<WORD_LENGTH, Value, EncodingError, Memory>
{
    fn clone(&self) -> Self {
        Self {
            el: self.el.clone(),
            encode: self.encode.clone(),
            decode: self.decode.clone(),
        }
    }
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
        let mut a = Address::<ADDRESS_LENGTH>::from([0; ADDRESS_LENGTH]);
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
        keyword: Keyword,
        values: HashSet<Value>,
    ) -> Result<(), <Self as IndexADT<Keyword, Value>>::Error> {
        let words = (self.encode)(op, values).map_err(|e| Error::Conversion(format!("{e:?}")))?;
        let l = Self::hash_keyword(&keyword);
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

    async fn search(&self, keyword: &Keyword) -> Result<HashSet<Value>, Self::Error> {
        let l = Self::hash_keyword(keyword);
        let words = IVec::new(l, self.el.clone()).read().await?;
        (self.decode)(words).map_err(|e| Error::Conversion(format!("{e:?}")))
    }

    async fn insert(
        &self,
        keyword: Keyword,
        values: impl Sync + Send + IntoIterator<Item = Value>,
    ) -> Result<(), Self::Error> {
        self.push(Op::Insert, keyword, values.into_iter().collect())
            .await
    }

    async fn delete(
        &self,
        keyword: Keyword,
        values: impl Sync + Send + IntoIterator<Item = Value>,
    ) -> Result<(), Self::Error> {
        self.push(Op::Delete, keyword, values.into_iter().collect())
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ADDRESS_LENGTH, Findex, InMemory, IndexADT, address::Address, dummy_decode, dummy_encode,
        memory::MemoryEncryptionLayer,
    };
    use cosmian_crypto_core::{CsRng, Secret, define_byte_type, reexport::rand_core::SeedableRng};
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_insert_search_delete_search() {
        // Define a byte type, and use `Value` as an alias for 8-bytes values of
        // that type.
        type Value = Bytes<8>;

        define_byte_type!(Bytes);

        impl<const LENGTH: usize> TryFrom<usize> for Bytes<LENGTH> {
            type Error = String;
            fn try_from(value: usize) -> Result<Self, Self::Error> {
                Self::try_from(value.to_be_bytes().as_slice()).map_err(|e| e.to_string())
            }
        }

        const WORD_LENGTH: usize = 16;

        let mut rng = CsRng::from_entropy();
        let seed = Secret::random(&mut rng);
        let memory = MemoryEncryptionLayer::new(
            &seed,
            InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default(),
        );
        let findex = Findex::new(memory, dummy_encode::<WORD_LENGTH, Value>, dummy_decode);
        let cat_bindings = [
            Value::try_from(1).unwrap(),
            Value::try_from(3).unwrap(),
            Value::try_from(5).unwrap(),
        ];
        let dog_bindings = [
            Value::try_from(0).unwrap(),
            Value::try_from(2).unwrap(),
            Value::try_from(4).unwrap(),
        ];
        findex
            .insert("cat".to_string(), cat_bindings.clone())
            .await
            .unwrap();
        findex
            .insert("dog".to_string(), dog_bindings.clone())
            .await
            .unwrap();
        let cat_res = findex.search(&"cat".to_string()).await.unwrap();
        let dog_res = findex.search(&"dog".to_string()).await.unwrap();
        assert_eq!(
            cat_bindings.iter().cloned().collect::<HashSet<_>>(),
            cat_res
        );
        assert_eq!(
            dog_bindings.iter().cloned().collect::<HashSet<_>>(),
            dog_res
        );

        findex.delete("dog", dog_bindings).await.unwrap();
        findex.delete("cat", cat_bindings).await.unwrap();
        let cat_res = findex.search(&"cat".to_string()).await.unwrap();
        let dog_res = findex.search(&"dog".to_string()).await.unwrap();
        assert_eq!(HashSet::new(), cat_res);
        assert_eq!(HashSet::new(), dog_res);
    }
}
