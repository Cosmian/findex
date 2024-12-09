#[cfg(any(test, feature = "bench"))]
pub(crate) mod in_memory;

#[cfg(feature = "redis-mem")]
pub mod error;

#[cfg(feature = "redis-mem")]
pub(crate) mod redis;

#[cfg(feature = "redis-mem")]

pub mod memory {
    pub use crate::memory::error::MemoryError as error;
    pub use crate::memory::redis::RedisMemory;
}
