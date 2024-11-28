//! Redis implementation of the Findex backends.
use redis::{Commands, Connection};
use std::{
    fmt::{self, Debug, Display},
    hash::Hash,
    marker::PhantomData,
    ops::Deref,
    sync::{Arc, Mutex},
};

use crate::MemoryADT;

#[derive(Clone)]
pub struct RedisStore<Address: Hash + Eq, const WORD_LENGTH: usize> {
    // todo(hatem) : use connection manager
    connection: Arc<Mutex<Connection>>,
    write_script_hash: String,
    _marker_adr: PhantomData<Address>,
}

// Args that are passed to the LUA script are, in order:
// 1. Guard address.
// 2. Guard value.
// 3. Vector length.
// 4+. Vector elements (address, word).
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

const POISONED_LOCK_ERROR_MSG: &str = "Poisoned lock error";

impl<Address: Hash + Eq, const WORD_LENGTH: usize> Debug for RedisStore<Address, WORD_LENGTH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisMemory")
            .field("connection", &"<redis::Connection>") // We don't want to debug the actual connection
            .field("Addr type", &self._marker_adr)
            .finish()
    }
}

impl<Address: Hash + Eq, const WORD_LENGTH: usize> RedisStore<Address, WORD_LENGTH> {
    /// Connects to a Redis server using the given URL.
    pub async fn connect(url: &str) -> Result<Self, RedisStoreError> {
        let mut connection = match redis::Client::open(url) {
            Ok(client) => match client.get_connection() {
                Ok(con) => con,
                Err(e) => {
                    panic!("Failed to connect to Redis: {}", e);
                }
            },
            Err(e) => panic!("Error creating redis client: {:?}", e),
        };
        let write_script_hash = redis::cmd("SCRIPT")
            .arg("LOAD")
            .arg(GUARDED_WRITE_LUA_SCRIPT)
            .query(&mut connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            write_script_hash,
            _marker_adr: PhantomData,
        })
    }

    // todo(hatem) : add 'connect with manager' equivalent

    pub fn clear_indexes(&self) -> Result<(), redis::RedisError> {
        let safe_connection = &mut *self.connection.lock().expect(POISONED_LOCK_ERROR_MSG);
        redis::cmd("FLUSHDB").exec(safe_connection)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisStoreError(String);

impl std::error::Error for RedisStoreError {}

impl From<redis::RedisError> for RedisStoreError {
    fn from(err: redis::RedisError) -> Self {
        Self(err.to_string())
    }
}

impl Display for RedisStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Redis Memory Error: {}", self.0)
    }
}

impl<
        Address: Send + Sync + Hash + Eq + Debug + Clone + Deref<Target = [u8; ADDRESS_LENGTH]>,
        const ADDRESS_LENGTH: usize,
        const WORD_LENGTH: usize,
    > MemoryADT for RedisStore<Address, WORD_LENGTH>
{
    type Address = Address;
    type Error = RedisStoreError;
    type Word = [u8; WORD_LENGTH];

    async fn batch_read(
        &self,
        addresses: Vec<Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        let safe_connection = &mut *self.connection.lock().expect(POISONED_LOCK_ERROR_MSG);
        let refs: Vec<&[u8; ADDRESS_LENGTH]> =
            addresses.iter().map(|address| address.deref()).collect();
        safe_connection
            .mget::<_, Vec<_>>(&refs)
            .map_err(Self::Error::from)
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let mut safe_connection = self.connection.lock().expect(POISONED_LOCK_ERROR_MSG);
        let (guard_address, guard_value) = guard;
        let mut cmd = redis::cmd("EVALSHA")
            .arg(self.write_script_hash.clone())
            .arg(0)
            .arg(&*guard_address)
            .clone(); // Why cloning is necessary : https://stackoverflow.com/questions/64728534/how-to-resolve-creates-a-temporary-variable-which-is-freed-while-still-in-use
        cmd = if let Some(byte_array) = guard_value {
            cmd.arg(&byte_array).arg(bindings.len()).clone()
        } else {
            cmd.arg("false".to_string()).arg(bindings.len()).clone()
        };
        for (address, word) in bindings {
            cmd = cmd.arg(&*address).arg(&word).clone();
        }
        cmd.query(&mut safe_connection).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        test::memory::{
            test_guarded_write_concurrent, test_single_write_and_read, test_wrong_guard,
        },
        Address,
    };
    use futures::executor::block_on;
    use serial_test::serial;

    use super::*;

    pub fn get_redis_url() -> String {
        if let Ok(var_env) = std::env::var("REDIS_HOST") {
            format!("redis://{var_env}:6379")
        } else {
            "redis://localhost:6379".to_string()
        }
    }

    const TEST_ADR_WORD_LENGTH: usize = 16;

    async fn init_test_redis_db() -> RedisStore<Address<TEST_ADR_WORD_LENGTH>, TEST_ADR_WORD_LENGTH>
    {
        RedisStore::<Address<TEST_ADR_WORD_LENGTH>, TEST_ADR_WORD_LENGTH>::connect(&get_redis_url())
            .await
            .unwrap()
    }

    #[tokio::test]
    #[serial]
    async fn test_db_flush() -> Result<(), RedisStoreError> {
        let memory = init_test_redis_db().await;

        let addr = Address::from([1; 16]);
        let word = [2; 16];

        block_on(memory.guarded_write((addr.clone(), None), vec![(addr.clone(), word)])).unwrap();

        let result = block_on(memory.batch_read(vec![addr.clone()])).unwrap();
        assert_eq!(result, vec![Some([2; 16])]);
        memory.clear_indexes().unwrap();

        let result = block_on(memory.batch_read(vec![addr])).unwrap();
        assert_eq!(result, vec![None]);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_rw_seq() -> Result<(), RedisStoreError> {
        let memory = init_test_redis_db().await;
        memory.clear_indexes().unwrap();
        block_on(test_single_write_and_read(&memory, rand::random()));
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_guard_seq() -> Result<(), RedisStoreError> {
        let memory = init_test_redis_db().await;
        memory.clear_indexes().unwrap();
        block_on(test_wrong_guard(&memory, rand::random()));
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_rw_ccr() -> Result<(), RedisStoreError> {
        let memory = init_test_redis_db().await;
        memory.clear_indexes().unwrap();
        block_on(test_guarded_write_concurrent(memory, rand::random()));
        Ok(())
    }
}
