use std::{
    fmt::{self, Debug, Display},
    hash::Hash,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use redis::{Commands, FromRedisValue, ToRedisArgs};

use crate::MemoryADT;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisMemoryError(String);

impl std::error::Error for RedisMemoryError {}

impl From<redis::RedisError> for RedisMemoryError {
    fn from(err: redis::RedisError) -> Self {
        Self(err.to_string())
    }
}

impl Display for RedisMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Redis Memory Error: {}", self.0)
    }
}

#[derive(Clone)]
pub struct RedisMemory<Address: Hash + Eq, Value: AsRef<u8>> // TT TYPE REDUCTIBLE A UNE SLICE DE BYTE (IMPLMENTS 'asref<[u8]>' / deref)
{
    connection: Arc<Mutex<redis::Connection>>,
    _marker_adr: PhantomData<Address>,
    _marker_value: PhantomData<Value>,
}

impl<Address: Hash + Eq, Value:AsRef<u8>> Debug for RedisMemory<Address, Value> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisMemory")
            .field("connection", &"<redis::Connection>") // We don't want to debug the actual connection
            .field("Addr type", &self._marker_adr)
            .field("Value type", &self._marker_value)
            .finish()
    }
}

impl<Address: Hash + Eq, Value:AsRef<u8>> Default for RedisMemory<Address, Value> {
    fn default() -> Self {
        Self {
            connection: match redis::Client::open("redis://127.0.0.1:9999/") {
                Ok(client) => match client.get_connection() {
                    Ok(con) => Arc::new(Mutex::new(con)),
                    Err(e) => {
                        panic!("Failed to connect to Redis: {}", e);
                    }
                },
                Err(e) => panic!("Error creating redis client: {:?}", e),
            },
            _marker_adr: PhantomData,
            _marker_value: PhantomData,
        }
    }
}

/**
 * Flushes the Redis database.
 * WARNING: This is irreversible, do not run in production.
 */
#[cfg(test)]
impl<Address: Hash + Eq + Debug,  Value: AsRef<u8>> RedisMemory<Address, Value> {
    pub fn flush_db(&self) -> Result<(), redis::RedisError> {
        let safe_connection = &mut *self.connection.lock().expect("Poisoned lock.");
        redis::cmd("FLUSHDB").exec(safe_connection)?;
        Ok(())
    }
}

/**
 * The RedisMemory implementation of the MemoryADT trait.
 * All operations are - and should be - atomic.
 */
impl<Address: Send + Sync + Hash + Eq + Debug + Clone + ToRedisArgs,  Value: AsRef<u8> + Sync + ToRedisArgs + Send + FromRedisValue>
    MemoryADT for RedisMemory<Address, Value>
{
    type Address = Address;
    type Error = RedisMemoryError;
    type Word = Value;

    /**
     * Atomically reads the values at the given addresses.
     */
    async fn batch_read(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        let safe_connection = &mut *self.connection.lock().expect("Poisoned lock.");
        // TODO : give mget a slice of addresses instead of a vector
        let refs: Vec<&Address> = addresses.iter().collect::<Vec<&Address>>(); // Redis MGET requires references to the values
        safe_connection.mget::<_,Vec<_>>(&refs).map_err(Self::Error::from)
    }

    /**
     * Atomically writes the bindings if the guard is still valid.
     * Returns the current value on the guard's address.
     * If the result is equal to the guard's old value, the bindings get
     * written.
     *
     * Args that are passed to the LUA script are, in order :
     * 1. Guard address.
     * 2. Guard value.
     * 3. Vector length.
     * 4+. Vector elements (address, word).
     */
    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let mut safe_connection = self.connection.lock().expect("Poisoned lock.");
        let (guard_address, guard_value) = guard;

        const GUARDED_WRITE_LUA_SCRIPT: &str = r#"
        local guard_address = ARGV[1]
        local guard_value = ARGV[2]
        local length = ARGV[3]
        
        local value = redis.call('GET',ARGV[1])

        -- compare the value of the guard to the currently stored value
        if((value==false) or (not(value == false) and (guard_value == value))) then
            -- guard passed, loop over bindings and insert them
            for i = 4,(length*2)+3,2
            do
                redis.call('SET', ARGV[i], ARGV[i+1])
            end
        end
        return value
        "#;

        let script = redis::Script::new(GUARDED_WRITE_LUA_SCRIPT);
        let mut script_invocation = script.prepare_invoke();

        script_invocation.arg(guard_address);
        if let Some(byte_array) = guard_value {
            script_invocation.arg(&byte_array);
        } else {
            script_invocation.arg("false".to_string());
        }
        script_invocation.arg(bindings.len());
        for (address, word) in bindings {
            script_invocation.arg(address).arg(&word);
        }

        script_invocation.invoke(&mut safe_connection).map_err(|e| e.into())
    }
}



#[cfg(test)]
mod tests {
    
    use futures::executor::block_on;
    use redis::{RedisResult, RedisWrite, Value};

    use super::*;
    use crate::MemoryADT;

    #[derive(Clone, Debug, PartialEq)]
    struct ByteArray([u8; 1]);
    
    impl AsRef<u8> for ByteArray {
        fn as_ref(&self) -> &u8 {
            &self.0[0]
        }
    }

impl ToRedisArgs for ByteArray {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        // Use the same implementation as [u8] slices
        out.write_arg(&self.0)
    }
}

impl FromRedisValue for ByteArray {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        // Convert to bytes first using Redis's built-in conversion
        let bytes: Vec<u8> = FromRedisValue::from_redis_value(v)?;
        
        // Ensure we have exactly one byte
        if bytes.len() != 1 {
            return Err(redis::RedisError::from((
                redis::ErrorKind::TypeError,
                "Expected exactly one byte",
            )));
        }
        
        Ok(ByteArray([bytes[0]]))
    }
}

    #[test]
    fn test_flush_db() {
        let memory = RedisMemory::<u8, ByteArray>::default();
        memory.flush_db().unwrap();

        assert_eq!(
            block_on(memory.guarded_write((0, None), vec![(1, ByteArray([2]))])).unwrap(),
            None
        );

        assert_eq!(
            vec![Some(ByteArray([2]))],
            block_on(memory.batch_read(vec![1])).unwrap(),
        );
        memory.flush_db().unwrap(); // flush !

        assert_eq!(vec![None], block_on(memory.batch_read(vec![1])).unwrap(),);
    }


    #[test]
    fn test_vector_push() {
        let memory = RedisMemory::<u8, ByteArray>::default();
        memory.flush_db().unwrap(); // prevent future tests from failing

        assert_eq!(
            block_on(memory.guarded_write((0, None), vec![(6, ByteArray([9]))])).unwrap(),
            None
        );

        assert_eq!(
            block_on(memory.guarded_write((0, None), vec![(0, ByteArray([2])), (1, ByteArray([1])), (2, ByteArray([1]))])).unwrap(),
            None
        );
        assert_eq!(
            block_on(memory.guarded_write((0, None), vec![(0, ByteArray([4])), (3, ByteArray([2])), (4, ByteArray([2]))])).unwrap(),
            Some(ByteArray([2]))
        );
        assert_eq!(
            block_on(memory.guarded_write((0, Some(ByteArray([2]))), vec![(0, ByteArray([4])), (3, ByteArray([3])), (4, ByteArray([3]))]))
                .unwrap(),
            Some(ByteArray([2]))
        );
        assert_eq!(
            vec![Some(ByteArray([1])), Some(ByteArray([1])), Some(ByteArray([3])), Some(ByteArray([3]))],
            block_on(memory.batch_read(vec![1, 2, 3, 4])).unwrap(),
        );

    }

    #[test]
    #[ignore]
    fn test_batch_read_error_handling() {
        todo!("Not implemented");
    }

    #[test]
    #[ignore]
    fn test_guarded_write_error_handling() {
        todo!("Not implemented");
    }
}
