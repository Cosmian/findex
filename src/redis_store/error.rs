use std::fmt::Display;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisMemoryError {
    pub details: String,
}

impl std::error::Error for RedisMemoryError {}

impl From<redis::RedisError> for RedisMemoryError {
    fn from(err: redis::RedisError) -> Self {
        RedisMemoryError {
            details: err.to_string(),
        }
    }
}

impl Display for RedisMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Redis Memory Error: {}", self.details)
    }
}
