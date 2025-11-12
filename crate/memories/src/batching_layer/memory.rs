use std::{fmt::Debug, num::NonZeroUsize, sync::Arc};

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
    pub inner: Arc<M>,                // The actual memory that does the R/W operations.
    buffer: Arc<ThreadSafeBuffer<M>>, // The buffer that holds the operations to be batched.
}

impl<M: BatchingMemoryADT> Clone for MemoryBatcher<M> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            buffer: Arc::clone(&self.buffer),
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
    pub fn new(inner: M, capacity: NonZeroUsize) -> Self {
        Self {
            inner: Arc::new(inner),
            buffer: Arc::new(ThreadSafeBuffer::new(capacity)),
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
        // Assumes the vector is homogeneous, i.e. all operations are of the same type.
        // This should be guaranteed by the buffer.
        match ops[0] {
            Operation::Read(_) => {
                // Build combined address list while tracking which addresses belong to which
                // batch.
                let all_addresses: Vec<_> = ops
                    .iter()
                    .map(|op| match op {
                        Operation::Read((addresses, _)) => Ok(addresses.clone()),
                        _ => Err(MemoryBatcherError::Buffering(
                            crate::batching_layer::buffer::BufferError::TypeMismatch,
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()? // Short-circuit on first error.
                    .into_iter()
                    .flatten()
                    .collect();

                let mut words = self
                    .inner
                    .batch_read(all_addresses)
                    .await
                    .map_err(MemoryBatcherError::Memory)?;

                // Distribute results to each batch's sender.
                for (input_addresses, sender) in ops
                    .into_iter()
                    .map(|op| match op {
                        Operation::Read((addresses, sender)) => Ok((addresses, sender)),
                        _ => Err(MemoryBatcherError::Buffering(
                            crate::batching_layer::buffer::BufferError::TypeMismatch,
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .rev()
                {
                    let batch_results = words.split_off(words.len() - input_addresses.len()); // After this call, all_results will be left containing the elements [0, split_point).
                    sender
                        .send(Ok(batch_results))
                        .map_err(|_| MemoryBatcherError::<M>::ClosedChannel)?;
                }
            }
            Operation::Write(_) => {
                let (bindings, senders): (Vec<_>, Vec<_>) = ops
                    .into_iter()
                    .map(|op| match op {
                        Operation::Write((bindings, sender)) => Ok((bindings, sender)),
                        _ => Err(MemoryBatcherError::Buffering(
                            crate::batching_layer::buffer::BufferError::TypeMismatch,
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .unzip();

                let aggregated_writes_results = self
                    .inner
                    .batch_guarded_write(bindings)
                    .await
                    .map_err(MemoryBatcherError::Memory)?;

                for (res, sender) in aggregated_writes_results.into_iter().zip(senders) {
                    sender
                        .send(Ok(res))
                        .map_err(|_| MemoryBatcherError::<M>::ClosedChannel)?;
                }
            }
        };
        Ok(())
    }
}
