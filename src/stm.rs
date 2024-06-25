use std::future::Future;

/// A Software Transactional Memory: all operations exposed are atomic.
pub trait Stm {
    /// Address space.
    type Address;

    /// Word space.
    type Word;

    /// Memory error.
    type Error: std::error::Error;

    /// Reads the words from the given addresses.
    fn batch_read(
        &self,
        a: Vec<Self::Address>,
    ) -> impl Future<Output = Result<Vec<Option<Self::Word>>, Self::Error>>;

    /// Write the given words at the given addresses if the word currently stored at the guard
    /// address is the one given, and returns this guard word.
    fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        tasks: Vec<(Self::Address, Self::Word)>,
    ) -> impl Future<Output = Result<Option<Self::Word>, Self::Error>>;
}
