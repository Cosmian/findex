#[cfg(feature = "redis-mem")]
mod redis_mem;
#[cfg(feature = "redis-mem")]
pub use redis_mem::{RedisMemory, RedisMemoryError};

#[cfg(feature = "sqlite-mem")]
mod sqlite_mem;
#[cfg(feature = "sqlite-mem")]
pub use sqlite_mem::{SqliteMemory, SqliteMemoryError};

#[cfg(feature = "postgres-mem")]
mod postgresql_mem;
#[cfg(feature = "postgres-mem")]
pub use postgresql_mem::{PostgresMemory, PostgresMemoryError};

pub mod reexport {
    #[cfg(feature = "sqlite-mem")]
    pub use async_sqlite;
    pub use cosmian_findex;
    #[cfg(feature = "postgres-mem")]
    pub use deadpool_postgres;
    #[cfg(feature = "redis-mem")]
    pub use redis;
    #[cfg(feature = "postgres-mem")]
    pub use tokio;
    #[cfg(feature = "postgres-mem")]
    pub use tokio_postgres;
}
