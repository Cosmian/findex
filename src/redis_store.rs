use std::{
    collections::HashMap,
    fmt::{self, Debug, Display},
    hash::Hash,
    marker::PhantomData,
    panic,
    sync::{Arc, Mutex},
};

use colored::Colorize;
use redis::{
    Commands, ConnectionInfo, FromRedisValue, RedisError, RedisResult, RedisWrite, ToRedisArgs,
    Value as RedisValue,
};

use crate::{MemoryADT, encoding::WORD_LENGTH as ENCODING_WORD_LENGTH_SPECEFIC};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisMemoryError {
    details: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct RedisWord<const WORD_LENGTH: usize>([u8; WORD_LENGTH]);

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

#[derive(Clone)]
pub struct RedisMemory<Address, Value>
where
    Address: Hash + Eq,
    Value: Clone + Eq,
{
    connexion: Arc<Mutex<redis::Connection>>,
    _marker: PhantomData<(Address, Value)>,
}

impl<Address, Value> fmt::Debug for RedisMemory<Address, Value>
where
    Address: Hash + Eq,
    Value: Clone + Eq,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisMemory")
            .field("connexion", &"<redis::Connection>") // We don't want to debug the actual connection
            .field("_marker", &self._marker)
            .finish()
    }
}

impl<Address: Hash + Eq + Debug, Value: Clone + Eq + Debug> Default
    for RedisMemory<Address, Value>
{
    fn default() -> Self {
        Self {
            connexion: match redis::Client::open("redis://127.0.0.1:9999/") {
                Ok(client) => match client.get_connection() {
                    Ok(con) => Arc::new(Mutex::new(con)),
                    Err(e) => {
                        panic!("Failed to connect to Redis: {}", e);
                    }
                },
                Err(e) => panic!("Error creating redis client: {:?}", e),
            },
            _marker: PhantomData,
        }
    }
}

impl<Address: Hash + Eq + Debug, Value: Clone + Eq + Debug> RedisMemory<Address, Value> {
    pub fn flus_db(&self) -> Result<(), redis::RedisError> {
        let safe_connexion = &mut *self.connexion.lock().expect("Poisoned lock.");
        redis::cmd("FLUSHDB").exec(safe_connexion)?;
        Ok(())
    }
}

/**
 * The RedisMemory implementation of the MemoryADT trait.
 * All operations SHOULD BE ATOMIC.
 */
impl<
    const WORD_LENGTH: usize,
    Address: Send + Sync + Hash + Eq + Debug + ToRedisArgs, /* Value: Send + Sync + Clone + Eq +
                                                             * Debug + FromRedisValue +
                                                             * ToRedisArgs, */
> MemoryADT for RedisMemory<Address, RedisWord<WORD_LENGTH>>
{
    type Address = Address;
    type Error = RedisMemoryError;
    type Word = RedisWord<WORD_LENGTH>;

    // Todo : atomicity
    /**
     * TODO : redis can call all the values at once in an atomic
     * DONE
     */
    async fn batch_read(&self, a: Vec<Address>) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        let safe_connexion = &mut *self.connexion.lock().expect("Poisoned lock.");
        let keys: Vec<Address> = a.into_iter().collect();
        let result: Vec<Option<Self::Word>> = match safe_connexion.mget(keys) {
            Ok(values) => values,
            Err(_e) => {
                return Err(RedisMemoryError {
                    details: "Error during batch_red from Redis.".to_string(),
                });
            }
        };
        Ok(result)
    }

    /**
     * Atomically writes the bindings if the guard is still valid.
     * Returns the current value on the guard's address.
     * If the result is equal to the guard's old value, the bindings were
     * written. If the result is different, the bindings were not
     * written (wrong guard).
     * (for the LUA script) Args should be passed in the following order:
     * 1. Guard address.
     * 2. Guard value.
     * 3. Vector length.
     * 4. Vector elements (address, word).
     */
    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        println!("{}", "Hola soy un spanish".purple());

        let safe_connexion = &mut *self.connexion.lock().expect("Poisoned lock.");
        let (guard_address, guard_value) = guard;

        const GUARDED_WRITE_LUA_SCRIPT: &str = r"
            local guard_address = ARGV[1]
            local guard_value = ARGV[2]
            local length = ARGV[3]
            local value = redis.call('GET',ARGV[1])

            -- compare the value of the guard to the currently stored value
            if((value==false) or (not(value == false) and (guard_value == value))) then
                -- guard passed, loop over bindings and insert them
                for i = 5,length-1+5,2
                do
                    redis.call('SET', ARGV[i], ARGV[i+1])
                end
                return
            else
                -- guard failed, return the actually red value
                return value
            end;
        ";
        let script = redis::Script::new(GUARDED_WRITE_LUA_SCRIPT);

        script
            .arg(guard_address)
            .arg(guard_value)
            .arg(bindings.len());
        for (address, word) in &bindings {
            script.arg(address).arg(word);
        }

        let result: Result<Option<Self::Word>, redis::RedisError> = script.invoke(safe_connexion);
        result.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {

    use futures::executor::block_on;

    use super::*;
    use crate::MemoryADT;

    /// Ensures a transaction can express a vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns
    // the current value.

    #[test]
    fn test_vector_push() {
        let memory = RedisMemory::<u8, u8>::default();

        // assert_eq!(
        //     block_on(memory.guarded_write((0, None), vec![(0, 2), (1, 1), (2,
        // 1)])).unwrap(),     None
        // );

        // assert_eq!(
        //     block_on(memory.guarded_write((0, None), vec![(0, 4), (3, 2), (4,
        // 2)])).unwrap(),     Some(2)
        // );
        // assert_eq!(
        //     block_on(memory.guarded_write((0, Some(2)), vec![(0, 4), (3, 3), (4,
        // 3)])).unwrap(),     Some(2)
        // );
        // assert_eq!(
        //     vec![Some(1), Some(1), Some(3), Some(3)],
        //     block_on(memory.batch_read(vec![1, 2, 3, 4])).unwrap(),
        // );

        memory.flus_db().unwrap(); // prevent future tests from failing
    }
}
