//! Redis implementation of the Findex backends.
use std::{
    fmt::{self, Debug, Display},
    hash::Hash,
    marker::PhantomData,
    ops::Deref,
};

use redis::{aio::ConnectionManager, AsyncCommands};

use crate::MemoryADT;

#[derive(Clone)]
pub struct RedisStore<Address: Hash + Eq, const WORD_LENGTH: usize> {
    manager: ConnectionManager,
    write_script_hash: String,
    _marker_adr: PhantomData<Address>,
}

// Args that are passed to the LUA script are, in order:
// 1. Guard address.
// 2. Guard value.
// 3. Vector length.
// 4+. Vector elements (address, word).
const GUARDED_WRITE_LUA_SCRIPT: &str = r"
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
";

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
        let client = redis::Client::open(url)?;
        let mut manager = client.get_connection_manager().await?;
        let write_script_hash = redis::cmd("SCRIPT")
            .arg("LOAD")
            .arg(GUARDED_WRITE_LUA_SCRIPT)
            .query_async(&mut manager)
            .await?;
        Ok(Self {
            manager,
            write_script_hash,
            _marker_adr: PhantomData,
        })
    }

    /// Connects to a Redis server with a `ConnectionManager`.
    pub async fn connect_with_manager(manager: ConnectionManager) -> Result<Self, RedisStoreError> {
        Ok(Self {
            manager: manager.clone(),
            write_script_hash: redis::cmd("SCRIPT")
                .arg("LOAD")
                .arg(GUARDED_WRITE_LUA_SCRIPT)
                .query_async(&mut manager.clone())
                .await?,
            _marker_adr: PhantomData,
        })
    }

    pub async fn clear_indexes(&self) -> Result<(), redis::RedisError> {
        redis::cmd("FLUSHDB")
            .query_async(&mut self.manager.clone())
            .await
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
        let refs: Vec<&[u8; ADDRESS_LENGTH]> = addresses.iter().map(|address| &**address).collect();
        self.manager
            .clone()
            .mget::<_, Vec<_>>(&refs)
            .await
            .map_err(Self::Error::from)
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let (guard_address, guard_value) = guard;
        let mut cmd = redis::cmd("EVALSHA")
            .arg(self.write_script_hash.clone())
            .arg(0)
            .arg(&*guard_address)
            .clone(); // Why cloning is necessary : https://stackoverflow.com/questions/64728534/how-to-resolve-creates-a-temporary-variable-which-is-freed-while-still-in-use
        cmd = if let Some(byte_array) = guard_value {
            cmd.arg(&byte_array).arg(bindings.len()).clone()
        } else {
            cmd.arg("false".to_owned()).arg(bindings.len()).clone()
        };
        for (address, word) in bindings {
            cmd = cmd.arg(&*address).arg(&word).clone();
        }
        cmd.query_async(&mut self.manager.clone())
            .await
            .map_err(std::convert::Into::into)
    }
}

#[cfg(feature = "test-utils")]
#[cfg(test)]
mod tests {

    use serial_test::serial;

    use super::*;
    use crate::{
        test::memory::{
            test_guarded_write_concurrent, test_single_write_and_read, test_wrong_guard,
        },
        Address,
    };

    pub(crate) fn get_redis_url() -> String {
        if let Ok(var_env) = std::env::var("REDIS_HOST") {
            format!("redis://{var_env}:6379")
        } else {
            "redis://localhost:6379".to_owned()
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

        memory
            .guarded_write((addr.clone(), None), vec![(addr.clone(), word)])
            .await
            .unwrap();

        let result = memory.batch_read(vec![addr.clone()]).await.unwrap();
        assert_eq!(result, vec![Some([2; 16])]);
        memory.clear_indexes().await.unwrap();

        let result = memory.batch_read(vec![addr]).await.unwrap();
        assert_eq!(result, vec![None]);
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_rw_seq() -> Result<(), RedisStoreError> {
        let memory = init_test_redis_db().await;
        memory.clear_indexes().await.unwrap();
        test_single_write_and_read(&memory, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_guard_seq() -> Result<(), RedisStoreError> {
        let memory = init_test_redis_db().await;
        memory.clear_indexes().await.unwrap();
        test_wrong_guard(&memory, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_rw_ccr() -> Result<(), RedisStoreError> {
        let memory = init_test_redis_db().await;
        memory.clear_indexes().await.unwrap();
        test_guarded_write_concurrent(memory, rand::random()).await;
        Ok(())
    }
}
