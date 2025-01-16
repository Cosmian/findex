use core::fmt::Display;

#[cfg(feature = "redis-mem")]
use redis::RedisError;

#[cfg(any(test, feature = "bench"))]
use super::in_memory_store::InMemoryError;

#[derive(Debug)]
pub enum MemoryError {
    #[cfg(any(test, feature = "bench"))]
    InMemory(InMemoryError),
    #[cfg(feature = "redis-mem")]
    Redis(RedisError),
}

impl Display for MemoryError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(any(test, feature = "bench"))]
            Self::InMemory(err) => write!(_f, "in_memory: {err}"),
            #[cfg(feature = "redis-mem")]
            Self::Redis(err) => write!(_f, "redis: {err}"),
            #[allow(unreachable_patterns)]
            _ => panic!("No error variant ?"),
        }
    }
}

impl std::error::Error for MemoryError {}

#[cfg(feature = "redis-mem")]
impl From<RedisError> for MemoryError {
    fn from(e: RedisError) -> Self {
        Self::Redis(e)
    }
}
