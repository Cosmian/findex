use std::fmt::{Debug, Display};

#[cfg(feature = "batch")]
pub use batch_findex_error::*;

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
    use cosmian_sse_memories::{MemoryADT, MemoryBatcherError};

    use super::*;

    #[derive(Debug)]
    pub enum BatchFindexError<M: MemoryADT>
    where
        <M as MemoryADT>::Word: Debug,
    {
        BatchingLayer(MemoryBatcherError<M>),
        Findex(Error<M::Address>),
    }

    impl<M: MemoryADT + Debug> Display for BatchFindexError<M>
    where
        <M as MemoryADT>::Address: Debug,
        <M as MemoryADT>::Word: Debug,
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::BatchingLayer(e) => write!(f, "Batching layer error: {e}"),
                Self::Findex(error) => write!(f, "Findex error: {error:?}"),
            }
        }
    }

    impl<M: MemoryADT + Debug> From<Error<M::Address>> for BatchFindexError<M>
    where
        <M as MemoryADT>::Word: Debug,
    {
        fn from(e: Error<M::Address>) -> Self {
            Self::Findex(e)
        }
    }

    impl<M: MemoryADT + Debug> From<MemoryBatcherError<M>> for BatchFindexError<M>
    where
        <M as MemoryADT>::Word: Debug,
    {
        fn from(e: MemoryBatcherError<M>) -> Self {
            Self::BatchingLayer(e)
        }
    }

    impl<M: MemoryADT + Debug> std::error::Error for BatchFindexError<M>
    where
        <M as MemoryADT>::Address: Debug,
        <M as MemoryADT>::Word: Debug,
    {
    }
}
