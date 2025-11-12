//! Thread-safe buffer for batching memory operations.
//!
//! Operations are accumulated until capacity is reached, then flushed in one
//! call to the inner memory. All operations are synchronized via `Mutex` to
//! ensure thread-safe concurrent access.

use std::{
    mem,
    num::{NonZero, NonZeroUsize},
    sync::Mutex,
};

use crate::{
    BatchingMemoryADT,
    batching_layer::operation::{Operation, PendingOperations},
};

struct Buffer<M: BatchingMemoryADT> {
    capacity: NonZeroUsize,
    data: PendingOperations<M>,
}

impl<M: BatchingMemoryADT> Buffer<M> {
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
    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        Self(Mutex::new(Buffer::<M> {
            capacity,
            data: Vec::with_capacity(capacity.into()),
        }))
    }

    pub(crate) fn shrink_capacity(&self) -> Result<Option<PendingOperations<M>>, BufferError> {
        let mut buffer = self.0.lock().expect("poisoned lock");
        if buffer.capacity == NonZero::new(1).unwrap() {
            return Ok(buffer.flush_if_not_empty());
        }
        buffer.capacity =
            NonZero::new(buffer.capacity.get() - 1).expect("buffer capacity should not reach zero");
        Ok(buffer.flush_if_not_empty())
    }

    pub(crate) fn push(
        &self,
        item: Operation<M>,
    ) -> Result<Option<PendingOperations<M>>, BufferError> {
        let mut buffer = self.0.lock().expect("poisoned lock");
        buffer.data.push(item);
        Ok(buffer.flush_if_not_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferError {
    TypeMismatch,
    Overflow,
    Underflow,
}

impl std::fmt::Display for BufferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TypeMismatch => write!(
                f,
                "Type mismatch: cannot mix read and write operations in the same buffer."
            ),
            Self::Overflow => write!(f, "Buffer overflow: cannot push below capacity."),
            Self::Underflow => write!(f, "Buffer underflow: cannot shrink capacity below zero."),
        }
    }
}

impl std::error::Error for BufferError {}
