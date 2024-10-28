use std::{
    fmt::{self, Debug, Display},
    hash::Hash,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use redis::{Commands, ToRedisArgs};

use crate::MemoryADT;

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

#[derive(Clone)]
pub struct RedisMemory<Address, const WORD_LENGTH: usize>
where
    Address: Hash + Eq,
    // Value: Clone + Eq,
{
    connection: Arc<Mutex<redis::Connection>>,
    _marker: PhantomData<Address>,
}

impl<Address: Hash + Eq, const WORD_LENGTH: usize> Debug for RedisMemory<Address, WORD_LENGTH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisMemory")
            .field("connection", &"<redis::Connection>") // We don't want to debug the actual connection
            .field("_marker", &self._marker)
            .finish()
    }
}

impl<Address: Hash + Eq, const WORD_LENGTH: usize> Default for RedisMemory<Address, WORD_LENGTH> {
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
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
impl<Address: Hash + Eq + Debug, const WORD_LENGTH: usize> RedisMemory<Address, WORD_LENGTH> {
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
impl<Address: Send + Sync + Hash + Eq + Debug + Clone + ToRedisArgs, const WORD_LENGTH: usize>
    MemoryADT for RedisMemory<Address, WORD_LENGTH>
{
    type Address = Address;
    type Error = RedisMemoryError;
    type Word = [u8; WORD_LENGTH];

    /**
     * Atomically reads the values at the given addresses.
     */
    async fn batch_read(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        let safe_connection = &mut *self.connection.lock().expect("Poisoned lock.");
        let refs: Vec<&Address> = addresses.iter().collect(); // Redis MGET requires references to the values
        let res: Vec<Option<Self::Word>> = safe_connection.mget(&refs).unwrap();
        Ok(res)
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
        let safe_connection = &mut *self.connection.lock().expect("Poisoned lock.");
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

        let result: Result<Option<Self::Word>, redis::RedisError> =
            script_invocation.invoke(safe_connection);

        result.map_err(Into::into)
    }
}

// cargo test --package findex --lib -- redis_store::redis_memory::tests
// --show-output
//
#[cfg(test)]
mod tests {

    use futures::executor::block_on;

    use super::*;
    use crate::{Address, MemoryADT};

    /// Ensures a transaction can express a vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns
    // the current value.

    #[test]
    fn test_vector_push() {
        // let memory = RedisMemory::<u8, u8>::default();
        // const ADDRESS_LENGTH: usize = 16;
        let memory = RedisMemory::<u8, 1>::default();
        memory.flush_db().unwrap(); // prevent future tests from failing

        assert_eq!(
            block_on(memory.guarded_write((0, None), vec![(6, [9])])).unwrap(),
            None
        );

        assert_eq!(
            block_on(memory.guarded_write((0, None), vec![(0, [2]), (1, [1]), (2, [1])])).unwrap(),
            None
        );

        assert_eq!(
            block_on(memory.guarded_write((0, None), vec![(0, [4]), (3, [2]), (4, [2])])).unwrap(),
            Some([2])
        );
        assert_eq!(
            block_on(memory.guarded_write((0, Some([2])), vec![(0, [4]), (3, [3]), (4, [3])]))
                .unwrap(),
            Some([2])
        );
        assert_eq!(
            vec![Some([1]), Some([1]), Some([3]), Some([3])],
            block_on(memory.batch_read(vec![1, 2, 3, 4])).unwrap(),
        );

        memory.flush_db().unwrap(); // prevent future tests from failing
    }
}
