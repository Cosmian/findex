use std::fmt::{Debug, Display};

use crate::{MemoryADT, memory::BatchingLayerError};

#[derive(Debug)]
pub enum BatchFindexError<M: MemoryADT> {
    BatchingLayerError(BatchingLayerError<M>),
    FindexError(Error<M::Address>),
}

impl<M: MemoryADT + Debug> Display for BatchFindexError<M>
where
    <M as MemoryADT>::Address: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchFindexError::BatchingLayerError(e) => write!(f, "Batching layer error: {e}"),
            BatchFindexError::FindexError(error) => write!(f, "Findex error: {error:?}"),
        }
    }
}

impl<M: MemoryADT + Debug> From<Error<M::Address>> for BatchFindexError<M> {
    fn from(e: Error<M::Address>) -> Self {
        BatchFindexError::FindexError(e)
    }
}

impl<M: MemoryADT + Debug> From<BatchingLayerError<M>> for BatchFindexError<M> {
    fn from(e: BatchingLayerError<M>) -> Self {
        BatchFindexError::BatchingLayerError(e)
    }
}

impl<M: MemoryADT + Debug> std::error::Error for BatchFindexError<M> where
    <M as MemoryADT>::Address: Debug
{
}

#[derive(Debug)]
pub enum Error<Address> {
    Parsing(String),
    Memory(String),
    Conversion(String),
    MissingValue(Address, usize),
    CorruptedMemoryCache,
}

impl<Address: Debug> Display for Error<Address> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<Address: Debug> std::error::Error for Error<Address> {}
