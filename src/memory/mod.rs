#[cfg(any(test, feature = "bench", feature = "redis-mem"))]
pub mod error;
#[cfg(feature = "redis-mem")]
pub mod redis;

#[cfg(any(test, feature = "bench"))]
pub mod in_memory;

pub mod memory {
    #[cfg(any(test, feature = "bench", feature = "redis-mem"))]
    pub use crate::memory::error::MemoryError;
    #[cfg(any(test, feature = "bench"))]
    pub use crate::memory::in_memory::InMemory;
    #[cfg(feature = "redis-mem")]
    pub use crate::memory::redis::RedisMemory;
}
