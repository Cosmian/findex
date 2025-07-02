use crate::{
    ADDRESS_LENGTH, Address, Decoder, Encoder, Findex, InMemory, IndexADT, MemoryADT, memory,
};
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    future::Future,
    hash::Hash,
    ops::Add,
    sync::{Arc, Mutex},
};

// ---------------------------- THE NEW ADT TYPES -----------------------------

// TODO : should all of these be sync ?
use futures::channel::oneshot;
pub trait BatcherSSEADT<Keyword: Send + Sync + Hash, Value: Send + Sync + Hash> {
    // TODO : maybe add the findex functions as trait
    // type Findex: IndexADT<Keyword, Value> + Send + Sync; // need those ? + Send + Sync;
    // type BatcherMemory: BatchingLayerADT<Address = Keyword, Word = Value, Error = Self::Error>;
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
}

// ---------------------------------- BufferedMemory Structure ----------------------------------
// It takes as inner memory any memory that implements the batcher ADT
// which is basically, having MemoryADT + The function batch_guarded_write

struct BufferedMemory<M: BatchingLayerADT>
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

// neded for findex constraints
impl<M: BatchingLayerADT + Send + Sync + Clone> Clone for BufferedMemory<M>
where
    M::Address: Clone + Send + Sync,
    M::Word: Send + Sync,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            buffer_size: self.buffer_size,
            pending_batches: Mutex::new(Vec::new()),
        }
    }
}

// This simply forward the BR/GW calls to the inner memory
// when findex instances (below) call the batcher's operations
impl<M: MemoryADT + Sync + Send> MemoryADT for Arc<M>
where
    M::Address: Send,
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
    EncodingError: Send + Sync + Debug,
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

impl<
    const WORD_LENGTH: usize,
    Keyword: Send + Sync + Hash + Eq,
    Value: Send + Sync + Hash + Eq,
    EncodingError: Send + Sync + Debug + std::error::Error,
    BatcherMemory: Send
        + Sync
        + Clone
        + BatchingLayerADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> BatcherSSEADT<Keyword, Value>
    for BatcherFindex<WORD_LENGTH, Value, EncodingError, BatcherMemory>
{
    // type Findex = Findex<WORD_LENGTH, Value, EncodingError, BatcherMemory>;
    // type BatcherMemory = BatcherMemory;
    type Error = EncodingError;

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
        entries: Vec<(
            Address<ADDRESS_LENGTH>,
            impl Sync + Send + IntoIterator<Item = Value>,
        )>,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    async fn batch_delete(
        &self,
        entries: Vec<(
            Address<ADDRESS_LENGTH>,
            impl Sync + Send + IntoIterator<Item = Value>,
        )>,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}
