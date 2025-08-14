#[cfg(feature = "batch")]
pub use batch_findex_error::*;

use std::fmt::{Debug, Display};

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

#[cfg(feature = "batch")]
pub mod batch_findex_error {
    use super::*;
    use cosmian_sse_memories::{BatchingLayerError, MemoryADT};

    #[derive(Debug)]
    pub enum BatchFindexError<M: MemoryADT> {
        BatchingLayer(BatchingLayerError<M>),
        Findex(Error<M::Address>),
        Encoding(String),
    }

    impl<M: MemoryADT + Debug> Display for BatchFindexError<M>
    where
        <M as MemoryADT>::Address: Debug,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::BatchingLayer(e) => write!(f, "Batching layer error: {e}"),
                Self::Findex(error) => write!(f, "Findex error: {error:?}"),
                Self::Encoding(msg) => write!(f, "Encoding error: {msg}"),
            }
        }
    }

    impl<M: MemoryADT + Debug> From<Error<M::Address>> for BatchFindexError<M> {
        fn from(e: Error<M::Address>) -> Self {
            Self::Findex(e)
        }
    }

    impl<M: MemoryADT + Debug> From<BatchingLayerError<M>> for BatchFindexError<M> {
        fn from(e: BatchingLayerError<M>) -> Self {
            Self::BatchingLayer(e)
        }
    }

    impl<M: MemoryADT + Debug> std::error::Error for BatchFindexError<M> where
        <M as MemoryADT>::Address: Debug
    {
    }
}
