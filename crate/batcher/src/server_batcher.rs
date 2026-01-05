mod buffer;
mod error;
mod memory;

use std::future::Future;

pub use error::Error;
pub use memory::{BatchingMemoryADT, MemoryBatcher};

/// Batches the server interface of a client-server protocol.
pub trait SBatcher: Send + Clone {
    type Error: std::error::Error;
    type RawInterface;

    fn new(raw: Self::RawInterface) -> Self;
    fn buffer_length(&self) -> usize;
    fn resize(&self, capacity: usize) -> Result<(), Self::Error>;
    fn shrink(&self) -> impl Send + Future<Output = Result<(), Self::Error>>;
}

/// Reduces an iterator of items into a single item using a fallible combination
/// function. Returns None if the iterator is empty, Some(Err) if combination
/// fails, Some(Ok) if successful.
fn try_reduce<T, E: std::error::Error>(
    it: impl IntoIterator<Item = T>,
    f: impl Fn(T, T) -> Result<T, E>,
) -> Option<Result<T, E>> {
    it.into_iter()
        .try_fold(None, |acc, rhs| {
            if let Some(lhs) = acc {
                Some(f(lhs, rhs)).transpose()
            } else {
                Ok(Some(rhs))
            }
        })
        .transpose()
}
