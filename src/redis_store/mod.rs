// Declare the module
mod redis_memory;

// Re-export the RedisMemory struct
pub use redis_memory::RedisMemory;

pub mod error;
pub use error::RedisMemoryError;

pub mod word;
pub use word::RedisWord;
