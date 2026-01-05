use crate::server_batcher::{
    Error, SBatcher,
    buffer::Buffer,
    memory::{
        BatchingMemoryADT, MemoryBinding,
        operation::{MemoryOperation, MemoryResult},
    },
    try_reduce,
};
use futures::channel::oneshot;
use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    ops::Add,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct MemoryBatcher<M: Send + Sync + Debug + Clone + BatchingMemoryADT>
where
    M::Address: Hash + Eq + Clone,
    M::Word: Clone,
{
    raw: Arc<M>,
    buffer: Arc<Mutex<Buffer<(oneshot::Sender<MemoryResult<M>>, MemoryOperation<M>)>>>,
}

impl<M: Send + Sync + Debug + Clone + BatchingMemoryADT> MemoryBatcher<M>
where
    M::Address: Hash + Eq + Clone,
    M::Word: Clone,
{
    async fn perform(
        &self,
        buffer: Vec<(oneshot::Sender<MemoryResult<M>>, MemoryOperation<M>)>,
    ) -> Result<(), Error<M::Error>> {
        if buffer.is_empty() {
            return Ok(());
        }

        match try_reduce(buffer.iter().map(|(_, op)| op).cloned(), Add::add)
            .expect("input buffer is not empty")?
        {
            MemoryOperation::BatchRead(addresses) => {
                self.perform_batch_read(buffer, addresses).await
            }
            MemoryOperation::GuardedWrite(guard_binding, new_bindings) => {
                self.perform_guarded_write(buffer, guard_binding, new_bindings)
                    .await
            }
            MemoryOperation::BatchGuardedWrite(guarded_bindings) => {
                self.perform_batch_guarded_write(buffer, guarded_bindings)
                    .await
            }
        }
    }

    async fn perform_batch_read(
        &self,
        buffer: Vec<(oneshot::Sender<MemoryResult<M>>, MemoryOperation<M>)>,
        addresses: Vec<M::Address>,
    ) -> Result<(), Error<M::Error>> {
        // Avoid reading from an address twice in case it is requested by more
        // than one operation.
        let unique_addresses = addresses
            .iter()
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let words = self
            .raw
            .batch_read(unique_addresses)
            .await
            .map_err(Error::Memory)?;

        let bindings = addresses.into_iter().zip(words).collect::<HashMap<_, _>>();

        for (channel, op) in buffer {
            match op {
                MemoryOperation::BatchRead(addresses) => channel
                    .send(MemoryResult::BatchRead(
                        addresses
                            .iter()
                            .map(|a| bindings.get(a).expect("missing word").clone())
                            .collect(),
                    ))
                    .map_err(|_| {
                        Error::Batcher("cannot send words back to the client instance".to_string())
                    })?,
                MemoryOperation::GuardedWrite(_, _) | MemoryOperation::BatchGuardedWrite(_) => {
                    panic!("cannot reduce batch reads into another operation")
                }
            }
        }
        Ok(())
    }

    async fn perform_guarded_write(
        &self,
        mut buffer: Vec<(oneshot::Sender<MemoryResult<M>>, MemoryOperation<M>)>,
        guard_binding: (M::Address, Option<M::Word>),
        new_bindings: Vec<MemoryBinding<M>>,
    ) -> Result<(), Error<M::Error>> {
        // A guarded write is a scalar operation.
        assert_eq!(1, buffer.len());
        let (channel, _) = buffer.pop().expect("buffer has length one");

        let guard_word = self
            .raw
            .guarded_write(guard_binding, new_bindings)
            .await
            .map_err(Error::Memory)?;

        channel
            .send(MemoryResult::GuardedWrite(guard_word))
            .map_err(|_| {
                Error::Batcher("cannot send words back to the client instance".to_string())
            })?;

        Ok(())
    }

    async fn perform_batch_guarded_write(
        &self,
        buffer: Vec<(oneshot::Sender<MemoryResult<M>>, MemoryOperation<M>)>,
        guarded_bindings: Vec<((M::Address, Option<M::Word>), Vec<MemoryBinding<M>>)>,
    ) -> Result<(), Error<M::Error>> {
        // The clippy lint is wrong here: as batch_guarded_write takes ownership
        // of guarded_bindings, collecting the iterator is required to clone the
        // addresses. Otherwise, the iterator would be keeping a reference to a
        // moved variable.
        #[allow(clippy::needless_collect)]
        let guard_addresses = guarded_bindings
            .iter()
            .map(|((a, _), _)| a.clone())
            .collect::<Vec<_>>();

        let guard_words = self
            .raw
            .batch_guarded_write(guarded_bindings)
            .await
            .map_err(Error::Memory)?;

        let guard_bindings = guard_addresses
            .into_iter()
            .zip(guard_words)
            .collect::<HashMap<_, _>>();

        for (channel, op) in buffer {
            match op {
                MemoryOperation::GuardedWrite((guard_address, _), _) => {
                    let guard_word = guard_bindings
                        .get(&guard_address)
                        .expect("missing word")
                        .clone();
                    channel
                        .send(MemoryResult::GuardedWrite(guard_word))
                        .map_err(|_| {
                            Error::Batcher(
                                "cannot send guard word back to the client instance".to_string(),
                            )
                        })?
                }
                MemoryOperation::BatchRead(_) | MemoryOperation::BatchGuardedWrite(_) => {
                    panic!("batch guarded write must be the reduction of guarded writes")
                }
            }
        }
        Ok(())
    }
}

impl<M: Send + Sync + Debug + Clone + BatchingMemoryADT> SBatcher for MemoryBatcher<M>
where
    M::Address: Hash + Eq + Clone,
    M::Word: Clone,
{
    type Error = Error<M::Error>;
    type RawInterface = M;

    fn new(raw: M) -> Self {
        Self {
            raw: Arc::new(raw),
            buffer: Arc::new(Mutex::new(Buffer::new())),
        }
    }

    fn buffer_length(&self) -> usize {
        self.buffer.lock().expect("poisoned lock").len()
    }

    fn resize(&self, capacity: usize) -> Result<(), Self::Error> {
        self.buffer
            .lock()
            .expect("poisoned lock")
            .resize(capacity)
            .map_err(Self::Error::Buffer)
    }

    async fn shrink(&self) -> Result<(), Self::Error> {
        if let Some(ops) = {
            let mut buffer = self.buffer.lock().expect("poisoned lock");
            buffer.shrink()
        } {
            // In case the buffer is full after shrinking it, the call to the
            // wrapped interface must be performed.
            self.perform(ops).await
        } else {
            Ok(())
        }
    }
}
