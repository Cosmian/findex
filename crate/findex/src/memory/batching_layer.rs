// ---------------------------------- BufferedMemory Structure ----------------------------------
// It takes as inner memory any memory that implements the batcher ADT
// which is basically, having MemoryADT + The function batch_guarded_write

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use futures::channel::{mpsc, oneshot};

use crate::{MemoryADT, adt::BatchingMemoryADT};

enum PendingBatchOps<M: BatchingMemoryADT + MemoryADT>
where
    M::Address: Clone,
{
    PendingReads(
        Mutex<
            Vec<(
                Vec<M::Address>,
                oneshot::Sender<Result<Vec<Option<M::Word>>, M::Error>>,
            )>,
        >,
    ),
    PendingWrites(
        Mutex<
            Vec<(
                ((M::Address, Option<M::Word>), Vec<(M::Address, M::Word)>),
                oneshot::Sender<Result<Option<M::Word>, M::Error>>,
            )>,
        >,
    ),
}

pub struct MemoryBatcher<M: BatchingMemoryADT>
// memory batcher
where
    M::Address: Clone,
{
    inner: M, // the actual memory layer that implements the actual network / memory call
    capacity: AtomicUsize, // n
    pending_ops: PendingBatchOps<M>, // ceci doit etre appelé buffer
}

impl<M: BatchingMemoryADT + Send> MemoryBatcher<M>
where
    <M as MemoryADT>::Address: Clone,
{
    pub fn new_reader(inner: M, buffer_size: AtomicUsize) -> Self {
        Self {
            inner,
            capacity: buffer_size,
            pending_ops: PendingBatchOps::PendingReads(Mutex::new(Vec::new())),
        }
    }

    pub fn new_writer(inner: M, buffer_size: AtomicUsize) -> Self {
        Self {
            inner,
            capacity: buffer_size,
            pending_ops: PendingBatchOps::PendingWrites(Mutex::new(Vec::new())),
        }
    }

    // atomically decrement the buffer size, needed on inserts/deletes
    pub(crate) fn decrement_capacity(&self) -> () {
        // `fetch_sub` returns the previous value, so if it was 1, it means the buffer's job is done
        let _ = self.capacity.fetch_sub(1, Ordering::SeqCst);
    }

    async fn flush(&self) -> Result<(), M::Error> {
        match &self.pending_ops {
            PendingBatchOps::PendingReads(read_ops) => {
                // maybe add a check that the capacities are correct
                let batches: Vec<(
                    Vec<M::Address>,
                    oneshot::Sender<Result<Vec<Option<M::Word>>, M::Error>>,
                )> = {
                    let mut pending = read_ops.lock().unwrap();
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
            PendingBatchOps::PendingWrites(write_ops) => {
                // maybe add a check that the capacities are correct
                let batches = {
                    let mut pending = write_ops.lock().unwrap();
                    if pending.is_empty() {
                        return Ok(());
                    }
                    std::mem::take(&mut *pending)
                };

                let (bindings, senders): (Vec<_>, Vec<_>) = batches.into_iter().unzip();

                let res = self.inner.batch_guarded_write(bindings).await?;
                // Distribute results to each batch's sender
                for (res, sender) in res.into_iter().zip(senders) {
                    let _ = sender.send(Ok(res));
                }
                Ok(())
            }
        }?;
        Ok(())
    }
}

impl<M: BatchingMemoryADT + Send + Sync> MemoryADT for MemoryBatcher<M>
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
        match &self.pending_ops {
            PendingBatchOps::PendingWrites(_) => panic!(
                "`batch_read` is called on a writer MemoryBatcher, make sure to use `new_reader` during initialization."
            ),
            PendingBatchOps::PendingReads(read_ops) => {
                // Create a channel for this batch
                let (sender, receiver) = oneshot::channel();
                let should_flush;

                // Add to pending batches
                {
                    let mut pending = read_ops.lock().unwrap();
                    pending.push((addresses, sender));

                    // Determine if we should flush

                    should_flush = pending.len() == self.capacity.load(Ordering::SeqCst);
                    if pending.len() > self.capacity.load(Ordering::SeqCst) {
                        panic!(
                            "this isn't supposed to happen, by design, change this to an error case later"
                        )
                    }
                }
                // Flush if buffer is full
                // only 1 thread will have this equal to true
                if should_flush {
                    self.flush().await?;
                }

                // Wait for results
                receiver.await.map_err(|_| {
                    // TODO This is a placeholder that will need to be replaced later
                    panic!("Channel closed unexpectedly ?")
                })?
            }
        }
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        match &self.pending_ops {
            PendingBatchOps::PendingReads(_) => panic!("what's happenning ?"),
            PendingBatchOps::PendingWrites(write_ops) => {
                let (sender, receiver) = oneshot::channel();
                let should_flush;

                // Add to pending batches
                {
                    let mut pending = write_ops.lock().unwrap();
                    pending.push(((guard, bindings), sender));

                    let capacity = self.capacity.load(Ordering::SeqCst);
                    if pending.len() > capacity {
                        // TODO: determin if this should be kept
                        panic!(
                            "this isn't supposed to happen, by design, change this to an error case later"
                        )
                    }
                    should_flush = pending.len() == capacity;
                }

                // Flush if buffer is full
                // only caller thread will have this equal to true
                if should_flush {
                    self.flush().await?;
                }

                // Wait for results
                receiver.await.map_err(|_| {
                    // TODO This is a placeholder that will need to be replaced later
                    panic!("Channel closed unexpectedly ?")
                })?
            }
        }
    }
}

// This simply forwards the BR/GW calls to the inner memory
// when findex instances (below) call the batcher's operations
impl<M: BatchingMemoryADT + Sync + Send> MemoryADT for Arc<MemoryBatcher<M>>
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
}
