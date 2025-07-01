use std::{collections::HashSet, fmt::Debug, future::Future, hash::Hash, sync::Arc};

use crate::{ADDRESS_LENGTH, Address, Decoder, Encoder, Findex, IndexADT, MemoryADT};

pub trait BatcherSSEADT<Keyword: Send + Sync + Hash, Value: Send + Sync + Hash> {
    // TODO : maybe add the findex functions as trait
    type Findex: IndexADT<Keyword, Value>; // need those ? + Send + Sync;
    type BatcherMemory: BatchingLayerADT<Address = Keyword, Word = Value, Error = Self::Error>;
    type Error: Send + Sync + std::error::Error;

    /// Search the index for the values bound to the given keywords.
    fn batch_search(
        &self,
        keywords: Vec<&Keyword>,
    ) -> impl Future<Output = Result<Vec<HashSet<Value>>, Self::Error>>;

    /// Adds the given values to the index.
    fn batch_insert(
        &self,
        entries: Vec<(Keyword, impl Sync + Send + IntoIterator<Item = Value>)>,
    ) -> impl Send + Future<Output = Result<(), Self::Error>>;

    /// Removes the given values from the index.
    fn batch_delete(
        &self,
        entries: Vec<(Keyword, impl Sync + Send + IntoIterator<Item = Value>)>,
    ) -> impl Send + Future<Output = Result<(), Self::Error>>;
}

// Define BatchingLayerADT as a supertrait of MemoryADT
pub trait BatchingLayerADT: MemoryADT {
    // You only need to declare the NEW methods here
    // The associated types and existing methods from MemoryADT are inherited

    /// Writes a batch of guarded write operations with bindings.
    fn batch_guarded_write(
        &self,
        operations: Vec<(
            (Self::Address, Option<Self::Word>),
            Vec<(Self::Address, Self::Word)>,
        )>,
    ) -> impl Send + Future<Output = Result<Vec<Option<Self::Word>>, Self::Error>>;

    // This is the function that will create the N channel ... ?
}

impl<M: MemoryADT> MemoryADT for Arc<M> {
    type Address = M::Address;
    type Word = M::Word;
    type Error = M::Error;

    fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> impl Send + Future<Output = Result<Vec<Option<Self::Word>>, Self::Error>> {
        (**self).batch_read(addresses)
    }

    fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> impl Send + Future<Output = Result<Option<Self::Word>, Self::Error>> {
        (**self).guarded_write(guard, bindings)
    }
}

#[derive(Debug)]
pub struct BatcherFindex<
    const WORD_LENGTH: usize,
    Value: Send + Sync + Hash + Eq,
    EncodingError: Send + Sync + Debug,
    BatcherMemory: Send + Sync + BatchingLayerADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> {
    encode: Arc<Encoder<Value, BatcherMemory::Word, EncodingError>>,
    decode: Arc<Decoder<Value, BatcherMemory::Word, EncodingError>>,
}
// batching_layer: Arc<BatcherMemory>,
// findex: Findex<WORD_LENGTH, Value, EncodingError, Arc<BatcherMemory>>,
impl<
    const WORD_LENGTH: usize,
    Value: Send + Sync + Hash + Eq,
    BatcherMemory: Send
        + Sync
        + Clone
        + BatchingLayerADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
    EncodingError: Send + Sync + Debug,
> BatcherFindex<WORD_LENGTH, Value, EncodingError, BatcherMemory>
{
    pub fn new(
        encode: Encoder<Value, BatcherMemory::Word, EncodingError>,
        decode: Decoder<Value, BatcherMemory::Word, EncodingError>,
    ) -> Self {
        Self {
            encode: Arc::new(encode),
            decode: Arc::new(decode),
        }
    }
}
