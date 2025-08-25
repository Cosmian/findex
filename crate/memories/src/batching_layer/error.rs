use std::fmt::{Debug, Display};

use futures::channel::oneshot::Canceled;

use crate::{
    MemoryADT,
    batching_layer::{buffer::BufferError, operation::MemoryOutput},
};

#[derive(Debug)]
pub enum MemoryBatcherError<M: MemoryADT>
where
    M::Word: std::fmt::Debug,
{
    // The from<M::Error> cannot be implemented due to conflicting
    // implementations with Rust's `core` library.
    Memory(M::Error),
    Channel(String),
    InternalBuffering(BufferError),
    WrongResultType(MemoryOutput<M>),
}

impl<M: MemoryADT> Display for MemoryBatcherError<M>
where
    M::Word: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(err) => write!(f, "Memory error: {:?}", err),
            Self::Channel(msg) => {
                write!(f, "Channel closed unexpectedly: {}", msg)
            }
            Self::InternalBuffering(err) => write!(f, "Internal buffering error: {:?}", err),
            Self::WrongResultType(out) => {
                write!(
                    f,
                    "Wrong result type, expected {:?}",
                    match out {
                        MemoryOutput::Read(_) => "Read, got Write.",
                        MemoryOutput::Write(_) => "Write, got Read.",
                    }
                )
            }
        }
    }
}

impl<M: MemoryADT> From<Canceled> for MemoryBatcherError<M>
where
    M::Word: std::fmt::Debug,
{
    // Does the error really not contain any additional information?
    fn from(_: Canceled) -> Self {
        Self::Channel(
            "The sender was dropped before sending its results with the `send` function."
                .to_string(),
        )
    }
}

impl<M: MemoryADT> From<BufferError> for MemoryBatcherError<M>
where
    M::Word: std::fmt::Debug,
{
    fn from(e: BufferError) -> Self {
        Self::InternalBuffering(e)
    }
}

impl<M: MemoryADT + Debug> std::error::Error for MemoryBatcherError<M> where M::Word: std::fmt::Debug
{}
