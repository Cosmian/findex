use crate::{ADDRESS_LENGTH, Address, Decoder, Encoder, Findex, IndexADT, MemoryADT};
use std::fmt::Display;
use std::{
    collections::HashSet,
    fmt::Debug,
    future::Future,
    hash::Hash,
    sync::{Arc, Mutex},
};
// TODO : should all of these be sync ?
use futures::channel::oneshot;

// ---------------------------- THE NEW ADT TYPES -----------------------------

// ---------------------------------- BufferedMemory Structure ----------------------------------
// It takes as inner memory any memory that implements the batcher ADT
// which is basically, having MemoryADT + The function batch_guarded_write

struct BufferedMemory<M: BatchingLayerADT + MemoryADT>
where
    M::Address: Clone,
{
    inner: M, // the actual memory layer that implements the actual network / memory call
    buffer_size: usize,
    pending_batches: Mutex<
        Vec<(
            Vec<M::Address>,
            oneshot::Sender<Result<Vec<Option<M::Word>>, M::Error>>,
        )>,
    >,
}

impl<M: BatchingLayerADT + Send> BufferedMemory<M>
where
    <M as MemoryADT>::Address: Clone,
{
    fn new(inner: M, buffer_size: usize) -> Self {
        Self {
            inner,
            buffer_size,
            pending_batches: Mutex::new(Vec::new()),
        }
    }

    async fn flush(&self) -> Result<(), M::Error> {
        // maybe add a check that the capacities are correct
        let batches: Vec<(
            Vec<M::Address>,
            oneshot::Sender<Result<Vec<Option<M::Word>>, M::Error>>,
        )> = {
            let mut pending = self.pending_batches.lock().unwrap();
            if pending.is_empty() {
                return Ok(());
            }
            std::mem::take(&mut *pending)
        };

        // Build combined address list while tracking which addresses belong to which batch
        let mut all_addresses = Vec::new();
        let mut batch_indices = Vec::new();

        for (individual_address_batch, _) in &batches {
            // Record the starting index for this batch
            // will be of the form (start_index, batch_length)
            batch_indices.push((all_addresses.len(), individual_address_batch.len()));
            // Add this batch's addresses to the combined list
            all_addresses.extend_from_slice(individual_address_batch);
        }

        // Execute the combined batch_read
        let mut all_results = self.inner.batch_read(all_addresses).await?;

        // Distribute results to each batch's sender
        // TODO: this is the most readable approach but we could optimize it ig ?
        for ((_, batch_len), (_, sender)) in batch_indices.into_iter().zip(batches) {
            // Always drain from index 0
            let batch_results = all_results.drain(0..batch_len).collect();
            let _ = sender.send(Ok(batch_results));
        }

        Ok(())
    }
}

impl<M: BatchingLayerADT + Send + Sync> MemoryADT for BufferedMemory<M>
where
    M::Address: Clone + Send,
    M::Word: Send,
{
    type Address = M::Address;
    type Word = M::Word;
    type Error = M::Error;

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }

        // Create a channel for this batch
        let (sender, receiver) = oneshot::channel();
        let should_flush;

        // Add to pending batches
        {
            let mut pending = self.pending_batches.lock().unwrap();
            pending.push((addresses, sender));

            // Determine if we should flush
            should_flush = pending.len() >= self.buffer_size;
        }

        // Flush if buffer is full
        // only 1 thread will have this equal to true
        if should_flush {
            self.flush().await?;
        }

        // Wait for results
        receiver.await.map_err(|_| {
            // This is a placeholder that will need to be replaced later
            panic!("Channel closed unexpectedly ?")
        })?
    }

    fn guarded_write(
        &self,
        _guard: (Self::Address, Option<Self::Word>),
        _bindings: Vec<(Self::Address, Self::Word)>,
    ) -> impl Send + Future<Output = Result<Option<Self::Word>, Self::Error>> {
        // shuts down the compiler warning for now
        async move { todo!("Implement guarded_write for BufferedMemory") }
    }
}

// Also implement BatchingLayerADT for BufferedMemory
impl<M: BatchingLayerADT + Send + Sync> BatchingLayerADT for BufferedMemory<M>
where
    M::Address: Clone + Send + Sync,
    M::Word: Send + Sync,
{
    fn batch_guarded_write(
        &self,
        _operations: Vec<(
            (Self::Address, Option<Self::Word>),
            Vec<(Self::Address, Self::Word)>,
        )>,
    ) -> impl Send + Future<Output = Result<Vec<Option<Self::Word>>, Self::Error>> {
        async move { todo!("Implement batch_guarded_write for BufferedMemory") }
    }
}

// // neded for findex constraints
// update lol no it's not needed
// impl<M: BatchingLayerADT + Send + Sync + Clone> Clone for BufferedMemory<M>
// where
//     M::Address: Clone + Send + Sync,
//     M::Word: Send + Sync,
// {
//     fn clone(&self) -> Self {
//         Self {
//             inner: self.inner.clone(),
//             buffer_size: self.buffer_size,
//             pending_batches: Mutex::new(Vec::new()),
//         }
//     }
// }

// This simply forward the BR/GW calls to the inner memory
// when findex instances (below) call the batcher's operations
impl<M: BatchingLayerADT + Sync + Send> MemoryADT for Arc<BufferedMemory<M>>
where
    M::Address: Send + Clone,
    M::Word: Send,
{
    type Address = M::Address;
    type Word = M::Word;
    type Error = M::Error;

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        (**self).batch_read(addresses).await
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        (**self).guarded_write(guard, bindings).await
    }

    // Implement other required methods similarly
}

// ---------------------------- BatcherFindex Structure -----------------------------
// He is a bigger findex that does findex operations but in batches lol

#[derive(Debug)]
pub struct BatcherFindex<
    const WORD_LENGTH: usize,
    Value: Send + Sync + Hash + Eq,
    EncodingError: Send + Sync + Debug,
    BatcherMemory: Clone
        + Send
        + Sync
        + BatchingLayerADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> {
    memory: BatcherMemory,
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
    EncodingError: Send + Sync + Debug + std::error::Error,
> BatcherFindex<WORD_LENGTH, Value, EncodingError, BatcherMemory>
{
    pub fn new(
        memory: BatcherMemory,
        encode: Encoder<Value, BatcherMemory::Word, EncodingError>,
        decode: Decoder<Value, BatcherMemory::Word, EncodingError>,
    ) -> Self {
        Self {
            memory,
            encode: Arc::new(encode),
            decode: Arc::new(decode),
        }
    }
}

// err type

#[derive(Debug)]
pub enum TemporaryError {
    DefaultGenericErrorForBatcher(String),
}

impl Display for TemporaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TemporaryError {}

// the new error type

impl<
    const WORD_LENGTH: usize,
    Keyword: Send + Sync + Hash + Eq,
    Value: Send + Sync + Hash + Eq,
    EncodingError: Send + Sync + Debug,
    BatcherMemory: Send
        + Sync
        + Clone
        + BatchingLayerADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> BatcherSSEADT<Keyword, Value>
    for BatcherFindex<WORD_LENGTH, Value, EncodingError, BatcherMemory>
{
    // type Findex = Findex<WORD_LENGTH, Value, EncodingError, BatcherMemory>;
    // type BatcherMemory = BatcherMemory;
    type Error = TemporaryError;

    async fn batch_search(
        &self,
        keywords: Vec<&Keyword>,
    ) -> Result<Vec<HashSet<Value>>, Self::Error> {
        let mut search_futures = Vec::new();
        let n = keywords.len();
        let buffered_memory = Arc::new(BufferedMemory::new(self.memory.clone(), n));

        for keyword in keywords {
            let buffered_memory_clone = buffered_memory.clone();
            let future = async move {
                // Create a temporary Findex instance using the shared batching layer
                let findex: Findex<
                    WORD_LENGTH,
                    Value,
                    EncodingError,
                    Arc<BufferedMemory<BatcherMemory>>,
                > = Findex::<WORD_LENGTH, Value, EncodingError, _>::new(
                    buffered_memory_clone,
                    *self.encode,
                    *self.decode,
                );

                // Execute the search
                findex.search(keyword).await
            };

            search_futures.push(future);
        }
        // at this point nothing is polled yet

        // Execute all futures concurrently and collect results
        let results = futures::future::join_all(search_futures).await;

        // Process results
        let mut output = Vec::with_capacity(results.len());
        for result in results {
            output.push(result.unwrap());
        }

        Ok(output)
    }

    async fn batch_insert(
        &self,
        _entries: Vec<(Keyword, impl Sync + Send + IntoIterator<Item = Value>)>,
    ) -> Result<(), Self::Error> {
        todo!("hello do not call me pls");
    }

    async fn batch_delete(
        &self,
        _entries: Vec<(Keyword, impl Sync + Send + IntoIterator<Item = Value>)>,
    ) -> Result<(), Self::Error> {
        todo!("I eat cement");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ADDRESS_LENGTH, Findex, InMemory, IndexADT, address::Address, dummy_decode, dummy_encode,
    };
    use cosmian_crypto_core::{CsRng, Secret, define_byte_type, reexport::rand_core::SeedableRng};
    use std::collections::HashSet;

    impl BatchingLayerADT for InMemory<Address<ADDRESS_LENGTH>, [u8; 16]> {
        fn batch_guarded_write(
            &self,
            _operations: Vec<(
                (Address<ADDRESS_LENGTH>, Option<[u8; 16]>),
                Vec<(Address<ADDRESS_LENGTH>, [u8; 16])>,
            )>,
        ) -> impl Send + Future<Output = Result<Vec<Option<[u8; 16]>>, Self::Error>> {
            async move { todo!("call me and you will regret it") }
        }
    }

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
        let garbage_memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();

        let findex = Findex::new(
            garbage_memory.clone(),
            dummy_encode::<WORD_LENGTH, Value>,
            dummy_decode,
        );
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

        // all of the previous garbage is the classic findex tests, now we will try to retrieve the same values using butcher findex
        let key1 = "cat".to_string();
        let key2 = "dog".to_string();
        let cat_dog_input = vec![&key1, &key2];

        let batcher_findex = BatcherFindex::<WORD_LENGTH, Value, _, _>::new(
            garbage_memory,
            |op, values| {
                dummy_encode::<WORD_LENGTH, Value>(op, values)
                    .map_err(|e| TemporaryError::DefaultGenericErrorForBatcher(e))
            },
            |words| {
                dummy_decode(words).map_err(|e| TemporaryError::DefaultGenericErrorForBatcher(e))
            },
        );

        let res = batcher_findex.batch_search(cat_dog_input).await.unwrap();
        println!("cat bindings: {cat_res:?}\n");
        println!("dog bindings: {dog_res:?}\n");
        println!("results of a batch_search performed on the vector Vec![cat, dog]: \n {res:?}\n");
    }
}
