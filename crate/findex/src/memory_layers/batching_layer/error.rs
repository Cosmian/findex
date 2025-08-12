use std::fmt::{Debug, Display};

use cosmian_sse_memories::MemoryADT;
use futures::channel::oneshot::Canceled;

#[derive(Debug)]
pub enum BatchingLayerError<M: MemoryADT> {
    Memory(M::Error),
    Mutex(String),
    Channel(String),
}

impl<M: MemoryADT> Display for BatchingLayerError<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(err) => write!(f, "Memory error: {:?}", err),
            Self::Mutex(msg) => write!(f, "Mutex error: {}", msg),
            Self::Channel(msg) => {
                write!(f, "Channel closed unexpectedly: {}", msg)
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
