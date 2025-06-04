use cosmian_findex::{Address, MemoryADT};
use redis::aio::ConnectionManager;
use std::{fmt, marker::PhantomData};

// Arguments passed to the LUA script, in order:
// 1. Guard address.
// 2. Guard value.
// 3. Vector length.
// 4+. Vector elements (address, word).
const GUARDED_WRITE_LUA_SCRIPT: &str = "
local guard_address = ARGV[1]
local guard_word    = ARGV[2]
local length        = ARGV[3]
local current_word  = redis.call('GET',guard_address)

-- If no word is found, nil is converted to 'false'.
if guard_word == tostring(current_word) then
    for i = 4,(length*2)+3,2
    do
        redis.call('SET', ARGV[i], ARGV[i+1])
    end
end
return current_word
";

#[derive(Debug, PartialEq)]
pub enum RedisMemoryError {
    RedisError(redis::RedisError),
}

impl fmt::Display for RedisMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RedisError(e) => write!(f, "Redis error: {}", e),
        }
    }
}

impl std::error::Error for RedisMemoryError {}

impl From<redis::RedisError> for RedisMemoryError {
    fn from(e: redis::RedisError) -> Self {
        Self::RedisError(e)
    }
}

#[derive(Clone)]
pub struct RedisMemory<Address, Word> {
    manager: ConnectionManager,
    script_hash: String,
    _marker: PhantomData<(Address, Word)>,
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

    #[cfg(feature = "test-utils")]
    pub async fn clear(&self) -> Result<(), RedisMemoryError> {
        redis::cmd("FLUSHDB")
            .query_async(&mut self.manager.clone())
            .await
            .map_err(RedisMemoryError::RedisError)
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
            .map_err(RedisMemoryError::RedisError)
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
            .map_err(RedisMemoryError::RedisError)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use cosmian_findex::{
        WORD_LENGTH, gen_seed, test_guarded_write_concurrent, test_rw_same_address,
        test_single_write_and_read, test_wrong_guard,
    };

    fn get_redis_url() -> String {
        std::env::var("REDIS_HOST").map_or_else(
            |_| "redis://localhost:6379".to_owned(),
            |var_env| format!("redis://{var_env}:6379"),
        )
    }

    #[tokio::test]
    async fn test_rw_seq() {
        let m = RedisMemory::connect(&get_redis_url()).await.unwrap();
        test_single_write_and_read::<WORD_LENGTH, _>(&m, gen_seed()).await
    }

    #[tokio::test]
    async fn test_guard_seq() {
        let m = RedisMemory::connect(&get_redis_url()).await.unwrap();
        test_wrong_guard::<WORD_LENGTH, _>(&m, gen_seed()).await
    }

    #[tokio::test]
    async fn test_collision_seq() {
        let m = RedisMemory::connect(&get_redis_url()).await.unwrap();
        test_rw_same_address::<WORD_LENGTH, _>(&m, gen_seed()).await
    }

    #[tokio::test]
    async fn test_rw_ccr() {
        let m = RedisMemory::connect(&get_redis_url()).await.unwrap();
        test_guarded_write_concurrent::<WORD_LENGTH, _>(&m, gen_seed(), None).await
    }
}
