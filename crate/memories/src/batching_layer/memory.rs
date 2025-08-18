// ---------------------------------- BufferedMemory Structure ----------------------------------
// It takes as inner memory any memory that implements the batcher ADT
// which is basically, having MemoryADT + The function batch_guarded_write

use futures::channel::oneshot;
use std::fmt::Debug;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use crate::batching_layer::BatchingLayerError;
use crate::{BatchingMemoryADT, MemoryADT};

type ReadOperation<M> = (
    Vec<<M as MemoryADT>::Address>,
    oneshot::Sender<Result<Vec<Option<<M as MemoryADT>::Word>>, <M as MemoryADT>::Error>>,
);

type WriteOperation<M> = (
    (
        (<M as MemoryADT>::Address, Option<<M as MemoryADT>::Word>),
        Vec<(<M as MemoryADT>::Address, <M as MemoryADT>::Word)>,
    ),
    oneshot::Sender<Result<Option<<M as MemoryADT>::Word>, <M as MemoryADT>::Error>>,
);

#[allow(clippy::type_complexity)] // refactoring this type will make the code unnecessarily more difficult to read without any actual benefit
enum PendingOperations<M: BatchingMemoryADT + MemoryADT>
where
    M::Address: Clone,
{
    PendingReads(Mutex<Vec<ReadOperation<M>>>),
    PendingWrites(Mutex<Vec<WriteOperation<M>>>),
}

impl<M: BatchingMemoryADT + MemoryADT> PendingOperations<M>
where
    M::Address: Clone,
{
    // Gets the lock of the buffer and returns its length; hence the name.
    pub fn lock_and_get_len(&self) -> Result<usize, BatchingLayerError<M>> {
        Ok(match self {
            Self::PendingReads(read_ops) => read_ops.lock()?.len(),
            Self::PendingWrites(write_ops) => write_ops.lock()?.len(),
        })
    }
}

pub struct MemoryBatcher<M: BatchingMemoryADT>
where
    M::Address: Clone,
{
    inner: M, // the actual memory layer that implements the actual network / memory call
    capacity: AtomicUsize, // capacity at which the operation should be executed
    buffer: PendingOperations<M>,
}

impl<M: BatchingMemoryADT + Send + Sync> MemoryBatcher<M>
where
    <M as MemoryADT>::Address: Clone,
{
    pub const fn new_reader(inner: M, capacity: AtomicUsize) -> Self {
        Self {
            inner,
            capacity,
            buffer: PendingOperations::PendingReads(Mutex::new(Vec::new())),
        }
    }

    pub const fn new_writer(inner: M, capacity: AtomicUsize) -> Self {
        Self {
            inner,
            capacity,
            buffer: PendingOperations::PendingWrites(Mutex::new(Vec::new())),
        }
    }

    // atomically decrement the buffer size, needed on inserts/deletes
    pub async fn decrement_capacity(&self) -> Result<(), BatchingLayerError<M>> {
        // `fetch_sub` returns the previous value, so if it was 1, it means the buffer's job is done
        let previous = self.capacity.fetch_sub(1, Ordering::SeqCst);
        match &self.buffer {
            PendingOperations::PendingReads(read_ops) => {
                if previous <= read_ops.lock()?.len() {
                    let _ = self.flush().await;
                }
            }
            PendingOperations::PendingWrites(write_ops) => {
                if previous <= write_ops.lock()?.len() {
                    let _ = self.flush().await;
                }
            }
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), BatchingLayerError<M>> {
        if self.buffer.lock_and_get_len()? > self.capacity.load(Ordering::SeqCst) {
            return Err(BatchingLayerError::BufferOverflow(
                "The buffer vector's length is greater than the capacity, this should not happen."
                    .to_owned(),
            ));
        }
        // check if the buffer is full
        if self.buffer.lock_and_get_len()? == self.capacity.load(Ordering::SeqCst) {
            match &self.buffer {
                PendingOperations::PendingReads(read_ops) => {
                    let batches = std::mem::take(&mut *read_ops.lock()?);

                    // Build combined address list while tracking which addresses belong to which batch
                    let all_addresses = batches
                        .iter()
                        .flat_map(|(addresses, _)| addresses.iter())
                        .cloned()
                        .collect();

                    let mut aggregated_reads_results = self
                        .inner
                        .batch_read(all_addresses)
                        .await
                        .map_err(BatchingLayerError::<M>::Memory)?;

                    // Distribute results to each batch's sender
                    for (input_addresses, sender) in batches.into_iter().rev() {
                        let split_point = aggregated_reads_results.len() - input_addresses.len(); // This is the point where the last batch's results start
                        let batch_results = aggregated_reads_results.split_off(split_point); // After this call, all_results will be left containing the elements [0, split_point)
                        sender.send(Ok(batch_results)).map_err(|_| {
                        // Upon failure, the vector we tried to send is returned in the Err varient, but it's explicitly ignored here to not extract information.
                        BatchingLayerError::<M>::Channel(
                            "The receiver end of this read operation was dropped before the `send` function could be called."
                                .to_owned(),
                        )
                    })?;
                    }
                }
                PendingOperations::PendingWrites(write_ops) => {
                    let batches = std::mem::take(&mut *write_ops.lock()?);

                    let (bindings, senders): (Vec<_>, Vec<_>) = batches.into_iter().unzip();

                    let aggregated_writes_results = self
                        .inner
                        .batch_guarded_write(bindings)
                        .await
                        .map_err(BatchingLayerError::<M>::Memory)?;

                    // Distribute results to each batch's sender
                    for (res, sender) in aggregated_writes_results.into_iter().zip(senders) {
                        sender.send(Ok(res)).map_err(|_| {
                        BatchingLayerError::<M>::Channel(
                            "The receiver end of this write operation was dropped before the `send` function could be called."
                                .to_owned(),
                        )
                    })?;
                    }
                }
            };
        }
        Ok(())
    }
}

impl<M: BatchingMemoryADT + Send + Sync + Debug> MemoryADT for MemoryBatcher<M>
where
    M::Address: Clone + Send,
    M::Word: Send,
{
    type Address = M::Address;
    type Word = M::Word;
    type Error = BatchingLayerError<M>;

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        match &self.buffer {
            PendingOperations::PendingWrites(_) => Err(BatchingLayerError::WrongOperation(
                "`batch_read` is called on a writer MemoryBatcher, make sure to use `new_reader` during initialization.".to_owned()
            )),
            PendingOperations::PendingReads(read_ops) => {
                // Create a channel for this batch.
                let (sender, receiver) = oneshot::channel();

                // Add to pending batches.
                {
                    let mut pending = read_ops.lock()?;
                    pending.push((addresses, sender));

                    // Determine if we should flush.
                }

                // Each thread tries to flush but only one will succeed and empty the buffer.
                self.flush().await?;

                // Wait for results.
                receiver
                    .await?
                    .map_err(|e| BatchingLayerError::<M>::Memory(e))
            }
        }
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        match &self.buffer {
            PendingOperations::PendingReads(_) => Err(BatchingLayerError::WrongOperation(
                "`guarded_write` is called on a reader MemoryBatcher, make sure to use `new_writer` during initialization.".to_owned()
            )),
            PendingOperations::PendingWrites(write_ops) => {
                let (sender, receiver) = oneshot::channel();

                {
                    let mut pending = write_ops.lock()?;
                    pending.push(((guard, bindings), sender));
                }

                self.flush().await?;

                receiver
                    .await?
                    .map_err(|e| BatchingLayerError::<M>::Memory(e))
            }
        }
    }
}

// This simply forwards the BR/GW calls to the inner memory
// when findex instances (below) call the batcher's operations
impl<M: BatchingMemoryADT + Sync + Send + Debug> MemoryADT for Arc<MemoryBatcher<M>>
where
    M::Address: Send + Clone,
    M::Word: Send,
{
    type Address = M::Address;
    type Word = M::Word;
    type Error = BatchingLayerError<M>;

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
}
