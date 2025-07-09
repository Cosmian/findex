use std::future::Future;

/// A Software Transactional Memory: all operations exposed are atomic.
pub trait MemoryADT {
    /// Address space.
    type Address;

    /// Word space.
    type Word;

    /// Memory error.
    type Error: Send + Sync + std::error::Error;

    /// Reads the words from the given addresses.
    fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> impl Send + Future<Output = Result<Vec<Option<Self::Word>>, Self::Error>>;

    /// Write the given bindings if the word currently stored at the guard
    /// address is the guard word, and returns this word.
    fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> impl Send + Future<Output = Result<Option<Self::Word>, Self::Error>>;
}
