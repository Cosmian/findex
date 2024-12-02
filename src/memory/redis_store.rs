use std::{
    fmt::{self, Debug},
    hash::Hash,
    marker::PhantomData,
    ops::Deref,
};

use redis::{AsyncCommands, aio::ConnectionManager};

use crate::MemoryADT;

use super::error::MemoryError;

#[derive(Clone)]
pub struct RedisStore<Address: Hash + Eq, const WORD_LENGTH: usize> {
    manager: ConnectionManager,
    script_hash: String,
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
            .field("connection", &"<redis::Connection>")
            .field("Addr type", &self._marker_adr)
            .finish()
    }
}

impl<Address: Hash + Eq, const WORD_LENGTH: usize> RedisStore<Address, WORD_LENGTH> {
    /// Connects to a Redis server with a `ConnectionManager`.
    pub async fn connect_with_manager(manager: ConnectionManager) -> Result<Self, MemoryError> {
        Ok(Self {
            manager: manager.clone(),
            script_hash: redis::cmd("SCRIPT")
                .arg("LOAD")
                .arg(GUARDED_WRITE_LUA_SCRIPT)
                .query_async(&mut manager.clone())
                .await?,
            _marker_adr: PhantomData,
        })
    }
    /// Connects to a Redis server using the given URL.
    pub async fn connect(url: &str) -> Result<Self, MemoryError> {
        let client = redis::Client::open(url)?;
        let manager = client.get_connection_manager().await?;
        Self::connect_with_manager(manager).await
    }

    pub async fn clear_indexes(&self) -> Result<(), redis::RedisError> {
        redis::cmd("FLUSHDB")
            .query_async(&mut self.manager.clone())
            .await
    }
}

impl<
    Address: Send + Sync + Hash + Eq + Debug + Clone + Deref<Target = [u8; ADDRESS_LENGTH]>,
    const ADDRESS_LENGTH: usize,
    const WORD_LENGTH: usize,
> MemoryADT for RedisStore<Address, WORD_LENGTH>
{
    type Address = Address;
    type Error = MemoryError;
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
            .arg(self.script_hash.clone())
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
        Address,
        test::memory::{
            test_guarded_write_concurrent, test_single_write_and_read, test_wrong_guard,
        },
    };

    pub(crate) fn get_redis_url() -> String {
        if let Ok(var_env) = std::env::var("REDIS_HOST") {
            format!("redis://{var_env}:6379")
        } else {
            "redis://localhost:6379".to_owned()
        }
    }

    const ADR_WORD_LENGTH: usize = 16;

    async fn init_test_redis_db()
    -> Result<RedisStore<Address<ADR_WORD_LENGTH>, ADR_WORD_LENGTH>, MemoryError> {
        RedisStore::<Address<ADR_WORD_LENGTH>, ADR_WORD_LENGTH>::connect(&get_redis_url()).await
    }

    #[tokio::test]
    #[serial]
    async fn test_rw_seq() -> Result<(), MemoryError> {
        let memory = init_test_redis_db().await.unwrap();
        memory.clear_indexes().await.unwrap();
        test_single_write_and_read(&memory, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_guard_seq() -> Result<(), MemoryError> {
        let memory = init_test_redis_db().await.unwrap();
        memory.clear_indexes().await.unwrap();
        test_wrong_guard(&memory, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_rw_ccr() -> Result<(), MemoryError> {
        let memory = init_test_redis_db().await.unwrap();
        memory.clear_indexes().await.unwrap();
        test_guarded_write_concurrent(memory, rand::random()).await;
        Ok(())
    }
}
