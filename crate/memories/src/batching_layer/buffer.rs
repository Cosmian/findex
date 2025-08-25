use std::{mem, sync::Mutex};

use crate::{
    BatchingMemoryADT,
    batching_layer::operation::{Operation, PendingOperations},
};

struct Buffer<M: BatchingMemoryADT> {
    capacity: usize, // the size at which the buffer should be flushed
    data: PendingOperations<M>,
}

impl<M: BatchingMemoryADT> Buffer<M> {
    // I think what you meant was to return the pending operation iff the buffer
    // is full... not if it is not empty! Right now, your buffer might not be
    // batching any operation.
    //
    // What you want is a `flush_when_full()` function:
    //
    // ```
    // if self.data.is_full() {
    //     Some(mem::take(&mut self.data))
    // } else {
    //     None
    // }
    // ```
    //
    // and maybe to inline it since this would make for a really tiny function.
    //
    /// Flushes the buffer if it contains data and returns the flushed
    /// operations. Returns None if the buffer is empty.
    fn flush_if_not_empty(&mut self) -> Option<PendingOperations<M>> {
        if !self.data.is_empty() {
            Some(mem::take(&mut self.data))
        } else {
            None
        }
    }
}

pub(crate) struct ThreadSafeBuffer<M: BatchingMemoryADT>(Mutex<Buffer<M>>);

impl<M> ThreadSafeBuffer<M>
where
    M: BatchingMemoryADT,
{
    pub(crate) fn new(capacity: usize) -> Self {
        Self(Mutex::new(Buffer::<M> {
            capacity,
            data: Vec::with_capacity(capacity),
        }))
    }

    pub(crate) fn shrink_capacity(&self) -> Result<Option<PendingOperations<M>>, BufferError> {
        let mut buffer = self.0.lock()?;
        if buffer.capacity == 0 {
            return Err(BufferError::Underflow);
        }
        buffer.capacity -= 1;
        Ok(buffer.flush_if_not_empty())
    }

    pub(crate) fn push(
        &self,
        item: Operation<M>,
    ) -> Result<Option<PendingOperations<M>>, BufferError> {
        let mut buffer = self.0.lock()?;
        if let Some(last_item) = buffer.data.last() {
            // This check ensures by transitivity that the buffer remains
            // homogeneous.
            if mem::discriminant(last_item) != mem::discriminant(&item) {
                return Err(BufferError::Heterogeneous);
            }
        }
        buffer.data.push(item);
        Ok(buffer.flush_if_not_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferError {
    Heterogeneous,
    Overflow,
    Underflow,
    // Just unwrap on-site instead.
    Mutex(String),
}

impl<M: BatchingMemoryADT> From<std::sync::PoisonError<std::sync::MutexGuard<'_, Buffer<M>>>>
    for BufferError
{
    fn from(e: std::sync::PoisonError<std::sync::MutexGuard<'_, Buffer<M>>>) -> Self {
        Self::Mutex(format!("Mutex poisoned: {}", e))
    }
}

impl std::fmt::Display for BufferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Heterogeneous => write!(
                f,
                "Type mismatch: cannot mix read and write operations in the same buffer."
            ),
            Self::Overflow => write!(f, "Buffer overflow: cannot push below capacity."),
            Self::Underflow => write!(f, "Buffer underflow: cannot shrink capacity below zero."),
            Self::Mutex(msg) => write!(f, "Mutex error: {}", msg),
        }
    }
}

impl std::error::Error for BufferError {}
