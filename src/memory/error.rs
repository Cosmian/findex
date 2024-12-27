use core::fmt::Display;

#[cfg(feature = "redis-mem")]
use redis::RedisError;

#[cfg(test)]
use super::in_memory::InMemoryError;

#[derive(Debug)]
pub enum MemoryError {
    #[cfg(test)]
    InMemory(InMemoryError),
    #[cfg(feature = "redis-mem")]
    Redis(RedisError),
}

impl Display for MemoryError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(test)]
            Self::InMemory(err) => write!(_f, "in_memory: {err}"),
            #[cfg(feature = "redis-mem")]
            Self::Redis(err) => write!(_f, "redis: {err}"),
            #[cfg(all(not(test), not(feature = "redis-mem")))]
            _ => panic!("no other variant"),
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
