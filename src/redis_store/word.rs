use std::fmt;

use redis::{
    FromRedisValue, RedisError, RedisResult, RedisWrite, ToRedisArgs, Value as RedisValue,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisWord<const WORD_LENGTH: usize>([u8; WORD_LENGTH]);

impl<const LENGTH: usize> fmt::Display for RedisWord<LENGTH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &self.0)
    }
}

impl<const LENGTH: usize> ToRedisArgs for RedisWord<LENGTH> {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        out.write_arg(&self.0);
    }
}

impl<const LENGTH: usize> FromRedisValue for RedisWord<LENGTH> {
    fn from_redis_value(v: &RedisValue) -> RedisResult<Self> {
        // Handle different Redis value types
        let bytes = match v {
            // Handle bulk string (most common case)
            RedisValue::BulkString(bytes) => bytes.clone(),

            // Handle simple string by converting to bytes
            RedisValue::SimpleString(s) => s.as_bytes().to_vec(),

            // Handle integers by converting to bytes
            RedisValue::Int(i) => {
                let s = i.to_string();
                s.as_bytes().to_vec()
            }

            // Return error for nil
            RedisValue::Nil => {
                return Err(RedisError::from((
                    redis::ErrorKind::TypeError,
                    "Unexpected Redis nil type",
                )));
            }

            // Handle other cases with appropriate error
            _ => {
                return Err(RedisError::from((
                    redis::ErrorKind::TypeError,
                    "Unexpected Redis value type",
                )));
            }
        };

        // Check if we have exactly WORD_LENGTH bytes
        if bytes.len() != LENGTH {
            return Err(RedisError::from((
                redis::ErrorKind::TypeError,
                "Invalid byte length for RedisWord",
                format!("Expected {} bytes, got {}", LENGTH, bytes.len()),
            )));
        }

        // Create a new array and copy bytes into it
        let mut word_array = [0u8; LENGTH];
        word_array.copy_from_slice(&bytes);

        Ok(RedisWord(word_array))
    }
}
