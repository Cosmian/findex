//! A memory batcher is an object that collects concurrent memory calls, groups
//! them to perform a single, batched, call to its underlying memory and finally
//! dispatch the results back to the concurrent memory calls. The difficulty is
//! to know how many call to wait before performing the batch call. The proposed
//! architecture maintains a `capacity` which counts the number of concurrent
//! calls that are batched. Upon terminating, caller processes notify the
//! batcher which then decrements its capacity.

#![allow(dead_code)]

use std::{
    fmt::{Debug, Display},
    sync::{Arc, Mutex},
};

use cosmian_findex::MemoryADT;

use buffer::Buffer;
use tokio::sync::mpsc::{Receiver, Sender, channel};

#[derive(Debug, PartialEq, Eq)]
enum BatcherError {
    BufferOverflow,
    BufferUnderflow,
    HeterogeneousBuffer,
    ReceiveError,
    SendOperationError,
    SendResultError,
    MemoryError(String),
}

impl Display for BatcherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatcherError::BufferOverflow => write!(f, "buffer overflow"),
            BatcherError::BufferUnderflow => write!(f, "buffer underflow"),
            BatcherError::HeterogeneousBuffer => write!(f, "heterogeneous buffer"),
            BatcherError::ReceiveError => write!(f, "receive error"),
            BatcherError::SendOperationError => write!(f, "send error"),
            BatcherError::SendResultError => write!(f, "send error"),
            BatcherError::MemoryError(e) => write!(f, "memory error: {e}"),
        }
    }
}

impl std::error::Error for BatcherError {}

pub enum MemoryOperation<M: MemoryADT> {
    Read(Vec<M::Address>),
    Write {
        guard: (M::Address, Option<M::Word>),
        bindings: Vec<(M::Address, M::Word)>,
    },
}

impl<M: MemoryADT> MemoryOperation<M> {
    fn same_kind(&self, other: &Self) -> bool {
        match (self, other) {
            (MemoryOperation::Read(_), MemoryOperation::Read(_)) => true,
            (MemoryOperation::Read(_), MemoryOperation::Write { .. }) => false,
            (MemoryOperation::Write { .. }, MemoryOperation::Read(_)) => false,
            (MemoryOperation::Write { .. }, MemoryOperation::Write { .. }) => true,
        }
    }
}

pub enum MemoryResult<M: MemoryADT> {
    Read(Vec<Option<M::Word>>),
    Write(Option<M::Word>),
}

#[derive(Debug, Clone)]
struct MemoryBatcher<M: MemoryADT> {
    snd: Arc<Mutex<Sender<Option<(Sender<MemoryResult<M>>, MemoryOperation<M>)>>>>,
    mem: M,
}

impl<M: MemoryADT> MemoryBatcher<M>
where
    M::Address: Clone,
{
    fn new(
        mem: M,
    ) -> (
        Receiver<Option<(Sender<MemoryResult<M>>, MemoryOperation<M>)>>,
        Self,
    ) {
        // This channel only allows one message per sender.
        let (snd, rcv) = channel(1);
        let batcher = Self {
            snd: Arc::new(Mutex::new(snd)),
            mem,
        };

        (rcv, batcher)
    }

    async fn unsuscribe(&self) -> Result<(), BatcherError> {
        let snd = { self.snd.lock().unwrap().clone() };
        snd.send(None)
            .await
            .map_err(|_| BatcherError::SendOperationError)
    }

    /// Runs the batcher process asynchronously.
    ///
    /// This process waits to receive `capacity` operations before processing
    /// them in batch. At any time, it can receive an empty message signaling
    /// the termination of a client process. In that case, it decreases its
    /// capacity.
    async fn run(
        self,
        mut rcv: Receiver<Option<(Sender<MemoryResult<M>>, MemoryOperation<M>)>>,
        mut capacity: usize,
    ) -> Result<(), BatcherError> {
        let mut buffer = Buffer::with_capacity(capacity);
        loop {
            let msg = rcv.recv().await.ok_or_else(|| BatcherError::ReceiveError)?;

            if let Some(msg) = msg {
                buffer.push(msg);
            } else {
                // An empty message means a sender terminated and unsubscribed
                // from the channel.
                capacity -= 1;
                if capacity == 0 {
                    return Ok(());
                }
            };

            if buffer.len() == capacity {
                buffer = self.manage_buffer(buffer).await?;
            } else if capacity < buffer.len() {
                return Err(BatcherError::BufferOverflow);
            }
        }
    }

    async fn manage_buffer(&self, buffer: Buffer<M>) -> Result<Buffer<M>, BatcherError> {
        let op = buffer
            .iter()
            .map(|(_, op)| op)
            .next()
            .expect("manage_buffer cannot be called on an empty buffer");

        if let MemoryOperation::Read(_) = op {
            self.manage_reads(buffer).await
        } else {
            self.manage_writes(buffer).await
        }
    }

    async fn manage_reads(&self, buffer: Buffer<M>) -> Result<Buffer<M>, BatcherError> {
        let capacity = buffer.capacity();
        let buffer = buffer
            .into_iter()
            .map(|(snd, op)| {
                if let MemoryOperation::Read(addresses) = op {
                    Ok((snd, addresses))
                } else {
                    Err(BatcherError::HeterogeneousBuffer)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let addresses = buffer
            .iter()
            .map(|(_, addresses)| addresses)
            .flatten()
            .cloned()
            .collect::<Vec<_>>();

        // Record the length to allow passing ownership of addresses next.
        let n = addresses.len();

        let words = self
            .mem
            .batch_read(addresses)
            .await
            .map_err(|e| BatcherError::MemoryError(e.to_string()))?;

        let mut words = words.into_iter();

        if words.len() == n {
            for (snd, addresses) in buffer {
                snd.send(MemoryResult::Read(
                    (0..addresses.len())
                        .map(|_| words.next().expect("length checked"))
                        .collect::<Vec<_>>(),
                ))
                .await
                .map_err(|_| BatcherError::SendResultError)?;
            }
            Ok(Buffer::with_capacity(capacity))
        } else {
            Err(BatcherError::MemoryError(
                "incorrect number of words".to_string(),
            ))
        }
    }

    async fn manage_writes(&self, buffer: Buffer<M>) -> Result<Buffer<M>, BatcherError> {
        todo!()
    }
}

impl<M: Send + Sync + Debug + MemoryADT> MemoryADT for MemoryBatcher<M>
where
    M::Word: Send + Sync,
    M::Address: Send + Sync,
{
    type Address = M::Address;

    type Word = M::Word;

    type Error = BatcherError;

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        let (snd, mut rcv) = channel(1);

        // Send the operation to the runner along with the back channel.
        let snd_ch = { self.snd.lock().unwrap().clone() };
        snd_ch
            .send(Some((snd, MemoryOperation::Read(addresses))))
            .await
            .map_err(|_| BatcherError::SendOperationError)?;

        // Await for its response.
        match rcv.recv().await.ok_or_else(|| BatcherError::ReceiveError)? {
            MemoryResult::Read(words) => Ok(words),
            MemoryResult::Write(_) => Err(BatcherError::MemoryError(
                "incorrect received memory-result type".to_string(),
            )),
        }
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        todo!()
    }
}

mod buffer {
    //! A Buffer simply is a typed vector used by a batcher.

    use std::{
        ops::{Deref, DerefMut},
        vec::IntoIter,
    };

    use super::*;

    pub struct Buffer<M: MemoryADT>(Vec<(Sender<MemoryResult<M>>, MemoryOperation<M>)>);

    impl<M: MemoryADT> Deref for Buffer<M> {
        type Target = Vec<(Sender<MemoryResult<M>>, MemoryOperation<M>)>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<M: MemoryADT> DerefMut for Buffer<M> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl<M: MemoryADT> Buffer<M> {
        pub fn with_capacity(capacity: usize) -> Self {
            Self(Vec::with_capacity(capacity))
        }
    }

    impl<M: MemoryADT> IntoIterator for Buffer<M> {
        type Item = (Sender<MemoryResult<M>>, MemoryOperation<M>);

        type IntoIter = IntoIter<(Sender<MemoryResult<M>>, MemoryOperation<M>)>;

        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter()
        }
    }
}

#[cfg(test)]
mod tests {
    use cosmian_findex::{InMemory, MemoryADT};

    use super::MemoryBatcher;

    #[tokio::test]
    async fn test_in_memory_batcher() {
        let memory = InMemory::<usize, usize>::default();
        memory
            .guarded_write((0, None), vec![(0, 0), (1, 1), (2, 2), (3, 3)])
            .await
            .unwrap();
        let (rcv, batcher) = MemoryBatcher::new(memory);

        let h1 = {
            let batcher = batcher.clone();
            tokio::spawn(async move {
                let v0 = batcher.batch_read(vec![0, 1]).await;
                batcher.unsuscribe().await.unwrap();
                assert_eq!(v0, Ok(vec![Some(0), Some(1)]));
            })
        };
        let h2 = {
            let batcher = batcher.clone();
            tokio::spawn(async move {
                let v1 = batcher.batch_read(vec![2, 3]).await;
                batcher.unsuscribe().await.unwrap();
                assert_eq!(v1, Ok(vec![Some(2), Some(3)]));
            })
        };
        let runner_handler = {
            let batcher = batcher.clone();
            tokio::spawn(async move { batcher.run(rcv, 2).await })
        };

        h1.await.unwrap();
        h2.await.unwrap();
        runner_handler.await.unwrap().unwrap();
    }
}
