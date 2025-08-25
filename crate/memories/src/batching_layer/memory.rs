use std::{fmt::Debug, sync::Arc};

use futures::channel::oneshot;

use crate::{
    BatchingMemoryADT, MemoryADT,
    batching_layer::{
        MemoryBatcherError,
        buffer::ThreadSafeBuffer,
        operation::{
            MemoryInput, MemoryOutput, Operation, OperationResultReceiver, PendingOperations,
        },
    },
};

pub struct MemoryBatcher<M: BatchingMemoryADT> {
    // Do not make it public. Plus, if you feel the need to say this is a
    // memory, call it memory and remove your comment.
    pub inner: M, // The actual memory that does the R/W operations.
    // The ThreadSafe in the name is just too much.
    buffer: Arc<ThreadSafeBuffer<M>>, // The buffer that holds the operations to be batched.
}

impl<M: BatchingMemoryADT + Clone> Clone for MemoryBatcher<M> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            buffer: self.buffer.clone(),
        }
    }
}

impl<M: BatchingMemoryADT + Send + Sync + Debug> MemoryADT for MemoryBatcher<M>
where
    M::Address: Clone,
    M::Word: std::fmt::Debug,
{
    type Address = M::Address;
    type Error = MemoryBatcherError<M>;
    type Word = M::Word;

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        let res = self.apply(MemoryInput::Read(addresses)).await?;

        if let MemoryOutput::Read(words) = res {
            Ok(words)
        } else {
            Err(MemoryBatcherError::WrongResultType(res))
        }
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let res = self.apply(MemoryInput::Write((guard, bindings))).await?;

        if let MemoryOutput::Write(word) = res {
            Ok(word)
        } else {
            Err(MemoryBatcherError::WrongResultType(res))
        }
    }
}

impl<M: BatchingMemoryADT + Send + Debug> MemoryBatcher<M>
where
    M::Address: Clone + Send,
    M::Word: Send + std::fmt::Debug,
{
    pub fn new(inner: M, n: usize) -> Self {
        if n == 0 {
            // No panic in production code! Use a `NonZeroUsize` instead.
            panic!("Buffer capacity must be greater than zero.");
        };
        Self {
            inner,
            buffer: Arc::new(ThreadSafeBuffer::new(n)),
        }
    }

    pub async fn unsubscribe(&self) -> Result<(), MemoryBatcherError<M>> {
        if let Some(ops) = self.buffer.shrink_capacity()? {
            self.manage(ops).await?;
        }
        Ok(())
    }

    async fn apply(&self, op: MemoryInput<M>) -> Result<MemoryOutput<M>, MemoryBatcherError<M>> {
        let (operation, receiver) = match op {
            MemoryInput::Read(addresses) => {
                let (sender, receiver) = oneshot::channel();
                (
                    Operation::Read((addresses, sender)),
                    OperationResultReceiver::<M>::Read(receiver),
                )
            }
            MemoryInput::Write((guard, bindings)) => {
                let (sender, receiver) = oneshot::channel();
                (
                    Operation::Write(((guard, bindings), sender)),
                    OperationResultReceiver::<M>::Write(receiver),
                )
            }
        };

        if let Some(ops) = self.buffer.push(operation)? {
            self.manage(ops).await?;
        }

        Ok(match receiver {
            OperationResultReceiver::Read(receiver) => {
                let result = receiver.await?.map_err(MemoryBatcherError::Memory)?;
                MemoryOutput::Read(result)
            }
            OperationResultReceiver::Write(receiver) => {
                let result = receiver.await?.map_err(MemoryBatcherError::Memory)?;
                MemoryOutput::Write(result)
            }
        })
    }

    async fn manage(&self, ops: PendingOperations<M>) -> Result<(), MemoryBatcherError<M>> {
        // Why not returning a typed buffer? But once again, I would rather go
        // toward heterogeneous operations...
        //
        // Assumes the vector is homogeneous, i.e. all operations are of the same type.
        // This should be guaranteed by the buffer.
        match ops[0] {
            Operation::Read(_) => {
                // Intuitively, this should be (maybe some details need to be fixed):
                //
                // ```
                // let (chans, addresses) = batch.into_iter().unzip();
                // let multiplicities = addresses.iter().map(Vector::len).collect::<Vec<_>>();
                //
                // let mut words = self.memory.batch_read(addresses.into_iter().flatten().collect()).await?;
                //
                // for (n_i, chan) in multiplicities.into_iter().zip(chans) {
                //     let words = /* take the next n_i words */;
                //     chan.send(words).await?;
                // }
                // ```
                //
                // Your code seems overly complex and performs at least one
                // unneeded address cloning.

                // Build combined address list while tracking which addresses belongs to which
                // batch.
                let all_addresses: Vec<_> = ops
                    .iter()
                    .flat_map(|op| match op {
                        // Yes, a typed buffer would definitely be better.
                        Operation::Read((addresses, _)) => addresses.clone(),
                        _ => unreachable!(
                            "Expected all operations to be reads, reaching this statement means \
                             the buffer has implementation flaws at the push level."
                        ),
                    })
                    .collect();

                let mut aggregated_reads_results = self
                    .inner
                    .batch_read(all_addresses)
                    .await
                    .map_err(MemoryBatcherError::Memory)?;

                // Distribute results to each batch's sender.
                for (input_addresses, sender) in ops
                    .into_iter()
                    .map(|op| match op {
                        Operation::Read((addresses, sender)) => (addresses, sender),
                        _ => unreachable!(
                            "Expected all operations to be reads, reaching this statement means \
                             the buffer has implementation flaws at the push level."
                        ),
                    })
                    .rev()
                {
                    // Please! these lines are 150+-character long!
                    let split_point = aggregated_reads_results.len() - input_addresses.len(); // This is the point where the last batch's results start.
                    let batch_results = aggregated_reads_results.split_off(split_point); // After this call, all_results will be left containing the elements [0, split_point).
                    sender.send(Ok(batch_results)).map_err(|_| {
                        // Upon failure, the vector we tried to send is returned in the Err variant,
                        // but it's explicitly ignored here to not extract information.
                        MemoryBatcherError::<M>::Channel(
                            "The receiver end of this read operation was dropped before the \
                             `send` function could be called."
                                .to_owned(),
                        )
                    })?;
                }
            }
            Operation::Write(_) => {
                // This arm is much cleaner, and is similar to my pseudo-code in
                // comment in the other arm. Both arms should be as symmetric as
                // possible.
                let (bindings, senders): (Vec<_>, Vec<_>) = ops
                    .into_iter()
                    .map(|op| match op {
                        Operation::Write((bindings, sender)) => (bindings, sender),
                        _ => unreachable!(),
                    })
                    .unzip();

                let aggregated_writes_results = self
                    .inner
                    .batch_guarded_write(bindings)
                    .await
                    .map_err(MemoryBatcherError::Memory)?;

                for (res, sender) in aggregated_writes_results.into_iter().zip(senders) {
                    sender.send(Ok(res)).map_err(|_| {
                        MemoryBatcherError::<M>::Channel(
                            // I'm pretty sure this is already present in `res`.
                            "The receiver end of this write operation was dropped before the \
                             `send` function could be called."
                                .to_owned(),
                        )
                    })?;
                }
            }
        };
        Ok(())
    }
}
