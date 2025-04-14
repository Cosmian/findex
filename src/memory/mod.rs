mod encryption_layer;
pub use encryption_layer::{KEY_LENGTH, MemoryEncryptionLayer};

#[cfg(any(test, feature = "test-utils"))]
mod in_memory_store;
#[cfg(any(test, feature = "test-utils"))]
pub use in_memory_store::InMemory;

#[cfg(feature = "redis-mem")]
mod redis_store;
#[cfg(feature = "redis-mem")]
pub use redis_store::{RedisMemory, RedisMemoryError};

#[cfg(feature = "sqlite-mem")]
pub mod sqlite_store;
#[cfg(feature = "sqlite-mem")]
pub use sqlite_store::{SqliteMemory, SqliteMemoryError};
