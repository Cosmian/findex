use std::{fmt, marker::PhantomData};

use redis::{RedisError, aio::ConnectionManager};

use crate::{Address, MemoryADT};

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
if ((value == false) or (guard_value == value)) then
    -- guard passed, loop over bindings and insert them
    for i = 4,(length*2)+3,2
    do
        redis.call('SET', ARGV[i], ARGV[i+1])
    end
end
return value
";

#[derive(Debug, PartialEq)]
pub struct RedisMemoryError {
    pub inner: RedisError,
}

impl fmt::Display for RedisMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Redis store memory error: {}", self.inner)
    }
}

impl std::error::Error for RedisMemoryError {}

impl From<RedisError> for RedisMemoryError {
    fn from(e: RedisError) -> Self {
        Self { inner: e }
    }
}

#[derive(Clone)]
pub struct RedisMemory<Address, Word> {
    manager: ConnectionManager,
    script_hash: String,
    _marker: PhantomData<(Address, Word)>, // to ensure type checking despite that Address & Word are intentionally unused in fields
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
    pub async fn connect_with_manager(
        mut manager: ConnectionManager,
    ) -> Result<Self, RedisMemoryError> {
        let script_hash = redis::cmd("SCRIPT")
            .arg("LOAD")
            .arg(GUARDED_WRITE_LUA_SCRIPT)
            .query_async(&mut manager)
            .await?;

        Ok(Self {
            manager,
            script_hash,
            _marker: PhantomData,
        })
    }

    /// Connects to a Redis server using the given URL.
    pub async fn connect(url: &str) -> Result<Self, RedisMemoryError> {
        let client = redis::Client::open(url)?;
        let manager = client.get_connection_manager().await?;
        Self::connect_with_manager(manager).await
    }
}

impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize> MemoryADT
    for RedisMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    type Address = Address<ADDRESS_LENGTH>;
    type Word = [u8; WORD_LENGTH];
    type Error = RedisMemoryError;

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        let mut cmd = redis::cmd("MGET");
        let cmd = addresses.iter().fold(&mut cmd, |c, a| c.arg(&**a));
        // Cloning the connection manager is cheap since it is an `Arc`.
        cmd.query_async(&mut self.manager.clone())
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
            .arg(&*guard_address)
            .arg(
                guard_value
                    .as_ref()
                    .map(|bytes| bytes.as_slice())
                    .unwrap_or(b"false".as_slice()),
            );

        let cmd = bindings
            .iter()
            .fold(cmd.arg(bindings.len()), |cmd, (a, w)| cmd.arg(&**a).arg(w));

        // Cloning the connection manager is cheap since it is an `Arc`.
        cmd.query_async(&mut self.manager.clone())
            .await
            .map_err(Self::Error::from)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::adt::test_utils::{
        test_guarded_write_concurrent, test_single_write_and_read, test_wrong_guard,
    };

    fn get_redis_url() -> String {
        std::env::var("REDIS_HOST").map_or_else(
            |_| "redis://localhost:6379".to_owned(),
            |var_env| format!("redis://{var_env}:6379"),
        )
    }

    #[tokio::test]
    async fn test_rw_seq() -> Result<(), RedisMemoryError> {
        let m = RedisMemory::connect(&get_redis_url()).await.unwrap();
        test_single_write_and_read(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), RedisMemoryError> {
        let m = RedisMemory::connect(&get_redis_url()).await.unwrap();
        test_wrong_guard(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), RedisMemoryError> {
        let m = RedisMemory::connect(&get_redis_url()).await.unwrap();
        test_guarded_write_concurrent(&m, rand::random()).await;
        Ok(())
    }
}
