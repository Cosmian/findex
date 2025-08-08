use futures::channel::oneshot::Canceled;
use std::fmt::{Debug, Display};

use crate::MemoryADT;

#[derive(Debug)]
pub enum BatchingLayerError<M: MemoryADT> {
    Memory(M::Error), // the from<M::Error> will not be implemented due to conflicting implementations with Rust's `core` library.  Use `map_err` instead of `?`.
    Mutex(String),
    Channel(String),
    BufferOverflow(String),
    WrongOperation(String),
}

impl<M: MemoryADT> Display for BatchingLayerError<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(err) => write!(f, "Memory error: {:?}", err),
            Self::Mutex(msg) => write!(f, "Mutex error: {}", msg),
            Self::Channel(msg) => {
                write!(f, "Channel closed unexpectedly: {}", msg)
            }
            Self::BufferOverflow(msg) => {
                write!(f, "Buffer overflow: {}", msg)
            }
            Self::WrongOperation(msg) => {
                write!(f, "Wrong operation: {}", msg)
            }
        }
    }
}

impl<M: MemoryADT> From<Canceled> for BatchingLayerError<M> {
    fn from(_: Canceled) -> Self {
        Self::Channel(
            "The sender was dropped before sending its results with the `send` function."
                .to_string(),
        )
    }
}

impl<M: MemoryADT, T> From<std::sync::PoisonError<T>> for BatchingLayerError<M> {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        Self::Mutex(format!("Mutex lock poisoned: {e}"))
    }
}

impl<M: MemoryADT + Debug> std::error::Error for BatchingLayerError<M> {}
