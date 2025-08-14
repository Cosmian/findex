mod address;
mod databases;
mod in_memory;

pub use address::Address;
#[cfg(feature = "postgres-mem")]
pub use databases::postgresql_mem::{PostgresMemory, PostgresMemoryError};
#[cfg(feature = "redis-mem")]
pub use databases::redis_mem::{RedisMemory, RedisMemoryError};
#[cfg(feature = "sqlite-mem")]
pub use databases::sqlite_mem::{SqliteMemory, SqliteMemoryError};
pub use in_memory::InMemory;

pub mod reexport {
    #[cfg(feature = "sqlite-mem")]
    pub use async_sqlite;
    #[cfg(feature = "postgres-mem")]
    pub use deadpool_postgres;
    #[cfg(feature = "redis-mem")]
    pub use redis;
    #[cfg(feature = "postgres-mem")]
    pub use tokio_postgres;
}

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

/// 16-byte addresses ensure a high collision resistance that poses virtually no
/// limitation on the index.
pub const ADDRESS_LENGTH: usize = 16;

/// A Software Transactional Memory: all operations exposed are atomic.
pub trait MemoryADT {
    /// Address space.
    type Address: Send;

    /// Word space.
    type Word: Send;

    /// Memory error.
    type Error: Send + std::error::Error;

    /// Reads the words from the given addresses.
    fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> impl Send + std::future::Future<Output = Result<Vec<Option<Self::Word>>, Self::Error>>;

    /// Write the given bindings if the word currently stored at the guard
    /// address is the guard word, and returns this word.
    fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> impl Send + std::future::Future<Output = Result<Option<Self::Word>, Self::Error>>;
}
