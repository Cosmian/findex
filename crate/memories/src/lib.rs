mod address;
mod adt;
mod databases;
mod in_memory;

pub use address::Address;
pub use adt::MemoryADT;
pub use in_memory::InMemory;

#[cfg(feature = "redis-mem")]
pub use databases::redis_mem::{RedisMemory, RedisMemoryError};

#[cfg(feature = "sqlite-mem")]
pub use databases::sqlite_mem::{SqliteMemory, SqliteMemoryError};

#[cfg(feature = "postgres-mem")]
pub use databases::postgresql_mem::{PostgresMemory, PostgresMemoryError};

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
