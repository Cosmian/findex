use core::fmt::Display;

#[cfg(feature = "redis-mem")]
use redis::RedisError;

#[derive(Debug)]
pub enum MemoryError {
    #[cfg(feature = "redis-mem")]
    Redis(RedisError),
}

impl Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "redis-mem")]
            Self::Redis(err) => write!(f, "redis: {err}"),
            #[cfg(not(feature = "redis-mem"))]
            _ => write!(f, "unknown error"),
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
