use std::{fmt, marker::PhantomData};

use redis::{AsyncCommands, RedisError, aio::ConnectionManager};

use crate::{ADDRESS_LENGTH, Address, MemoryADT};

// Arguments passed to the LUA script, in order:
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

#[derive(Debug, PartialEq)]
pub struct MemoryError {
    pub inner: RedisError,
}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Memory Error")
    }
}

impl std::error::Error for MemoryError {}

impl From<RedisError> for MemoryError {
    fn from(e: RedisError) -> Self {
        Self { inner: e }
    }
}

#[derive(Clone)]
pub struct RedisMemory<Address, Word> {
    pub manager: ConnectionManager,
    script_hash: String,
    a: PhantomData<Address>,
    w: PhantomData<Word>,
}

impl<Address, Word> fmt::Debug for RedisMemory<Address, Word> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisMemory")
            .field("connection", &"<redis::Connection>")
            .finish()
    }
}

impl<Address: Sync, Word: Sync> RedisMemory<Address, Word> {
    /// Connects to a Redis server with a `ConnectionManager`.
    pub async fn connect_with_manager(mut manager: ConnectionManager) -> Result<Self, MemoryError> {
        Ok(Self {
            manager: manager.clone(),
            script_hash: redis::cmd("SCRIPT")
                .arg("LOAD")
                .arg(GUARDED_WRITE_LUA_SCRIPT)
                .query_async(&mut manager)
                .await?,
            a: PhantomData,
            w: PhantomData,
        })
    }

    /// Connects to a Redis server using the given URL.
    pub async fn connect(url: &str) -> Result<Self, MemoryError> {
        let client = redis::Client::open(url)?;
        let manager = client.get_connection_manager().await?;
        Self::connect_with_manager(manager).await
    }

    pub async fn clear_redis_db(&self) -> Result<(), redis::RedisError> {
        redis::cmd("FLUSHDB")
            .query_async(&mut self.manager.clone())
            .await
    }
}

impl<const WORD_LENGTH: usize> MemoryADT
    for RedisMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    type Address = Address<ADDRESS_LENGTH>;
    type Error = MemoryError;
    type Word = [u8; WORD_LENGTH];

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        self.manager
            .clone()
            .mget(addresses.iter().map(|a| &**a).collect::<Vec<_>>())
            .await
            .map_err(Self::Error::from)
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let (guard_address, guard_value) = guard;
        let mut cmd = redis::cmd("EVALSHA");
        let cmd = cmd
            .arg(self.script_hash.as_str())
            .arg(0)
            .arg(&*guard_address);

        let cmd = if let Some(byte_array) = guard_value {
            cmd.arg(&byte_array)
        } else {
            cmd.arg("false")
        };

        let cmd = bindings
            .iter()
            .fold(cmd.arg(bindings.len()), |cmd, (a, w)| cmd.arg(&**a).arg(w));

        cmd.query_async(&mut self.manager.clone())
            .await
            .map_err(std::convert::Into::into)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::test::memory::{
        test_guarded_write_concurrent, test_single_write_and_read, test_wrong_guard,
    };

    fn get_redis_url() -> String {
        std::env::var("REDIS_HOST").map_or_else(
            |_| "redis://localhost:6379".to_owned(),
            |var_env| format!("redis://{var_env}:6379"),
        )
    }

    const WORD_LENGTH: usize = 16;

    #[tokio::test]
    async fn test_rw_seq() -> Result<(), MemoryError> {
        let m = RedisMemory::<_, [u8; WORD_LENGTH]>::connect(&get_redis_url())
            .await
            .unwrap();
        m.clear_redis_db().await.unwrap();
        test_single_write_and_read(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), MemoryError> {
        let m = RedisMemory::<_, [u8; WORD_LENGTH]>::connect(&get_redis_url())
            .await
            .unwrap();
        m.clear_redis_db().await.unwrap();
        test_wrong_guard(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), MemoryError> {
        let m = RedisMemory::<_, [u8; WORD_LENGTH]>::connect(&get_redis_url())
            .await
            .unwrap();
        m.clear_redis_db().await.unwrap();
        test_guarded_write_concurrent(&m, rand::random()).await;
        Ok(())
    }
}
