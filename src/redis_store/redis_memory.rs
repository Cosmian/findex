use std::{
    clone,
    fmt::{self, Debug},
    hash::Hash,
    marker::PhantomData,
    ops::Add,
    sync::{Arc, Mutex},
};

use colored::Colorize;
use redis::{Commands, Script, ToRedisArgs};

use super::{RedisMemoryError, RedisWord};
use crate::{Address, MemoryADT, encoding::WORD_LENGTH};

#[derive(Clone)]
pub struct RedisMemory<Address, const WORD_LENGTH: usize>
where
    Address: Hash + Eq,
    // Value: Clone + Eq,
{
    connexion: Arc<Mutex<redis::Connection>>,
    _marker: PhantomData<Address>,
}

impl<Address: Hash + Eq, const WORD_LENGTH: usize> Debug for RedisMemory<Address, WORD_LENGTH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisMemory")
            .field("connexion", &"<redis::Connection>") // We don't want to debug the actual connection
            .field("_marker", &self._marker)
            .finish()
    }
}

impl<Address: Hash + Eq, const WORD_LENGTH: usize> Default for RedisMemory<Address, WORD_LENGTH> {
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

impl<Address: Hash + Eq + Debug, const WORD_LENGTH: usize> RedisMemory<Address, WORD_LENGTH> {
    pub fn flush_db(&self) -> Result<(), redis::RedisError> {
        let safe_connexion = &mut *self.connexion.lock().expect("Poisoned lock.");
        redis::cmd("FLUSHDB").exec(safe_connexion)?;
        Ok(())
    }
}

// Implement ToRedisArgs for our byte array wrapper
struct ByteArrayWrapper<const N: usize>(Option<[u8; N]>);

impl<const N: usize> ToRedisArgs for ByteArrayWrapper<N> {
    // TODO : this function was autogen
    // affirm that it is a valid conversion
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + redis::RedisWrite,
    {
        match &self.0 {
            Some(array) => {
                // Convert the byte array to a slice and write it
                out.write_arg(array.as_slice())
            }
            None => {
                // Write an empty array or null value depending on your needs
                out.write_arg(&[][..])
            }
        }
    }
}

// // Helper function to convert Option<[u8; N]> to ByteArrayWrapper
// fn wrap_bytes<const N: usize>(bytes: Option<[u8; N]>) -> ByteArrayWrapper<N>
// {     ByteArrayWrapper(bytes)
// }

// impl<const N: usize> fmt::Debug for ByteArrayWrapper<N> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         match &self.0 {
//             Some(array) => write!(f, "ByteArrayWrapper({:?})", array),
//             None => write!(f, "ByteArrayWrapper(None)"),
//         }
//     }
// }

// add multiple arguments to a Command
fn array_arg<Address, const WORD_LENGTH: usize>(
    mut script: Script, // we need to take ownership of the Script
    entry_address: Address,
    entry_value: Option<[u8; WORD_LENGTH]>,
) -> Script
where
    Address: Send + Sync + Hash + Eq + Debug + ToRedisArgs + Clone,
{
    if let Some(byte_array) = entry_value {
        // TODO : is cloning sub optimal?
        let concatenated = format!("{:?}", byte_array);
        println!("Concatenated: {}", concatenated);

        script.arg(entry_address.clone()).arg(concatenated);
    }
    script
}

/**
 * The RedisMemory implementation of the MemoryADT trait.
 * All operations SHOULD BE ATOMIC.
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
        println!("{}", "Hola i am reading operation".yellow());
        let safe_connexion = &mut *self.connexion.lock().expect("Poisoned lock.");
        let refs: Vec<&Address> = addresses.iter().collect(); // Redis MGET requires references to the values
        let res: Vec<Option<Self::Word>> = safe_connexion.mget(&refs).unwrap();
        Ok(res)
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
        println!("{}", "Hola this is a read operation".purple());

        let safe_connexion = &mut *self.connexion.lock().expect("Poisoned lock.");
        let (guard_address, guard_value) = guard;
        // redis.log(redis.LOG_NOTICE, "Args length: " .. #ARGV)
        // redis.log(redis.LOG_NOTICE, "Hola " .. ARGV[1])
        // redis.log(redis.LOG_NOTICE, "Hola " .. ARGV[2])
        // redis.log(redis.LOG_NOTICE, "Hola " .. ARGV[3])
        // redis.log(redis.LOG_NOTICE, "Hola " .. ARGV[4])
        // redis.log(redis.LOG_NOTICE, "Hola " .. ARGV[5])

        const GUARDED_WRITE_LUA_SCRIPT: &str = r#"
            local guard_address = ARGV[1]
            local guard_value = ARGV[2]
            local length = ARGV[3]

            local value = redis.call('GET',ARGV[1])
            -- compare the value of the guard to the currently stored value

            if((value==false) or (not(value == nil) and (guard_value == value))) then
                -- guard passed, loop over bindings and insert them
                for i = 4,(length*2)+3,2
                do
                    redis.call('SET', ARGV[i], ARGV[i+1])
                end
            end
            return value
            "#;

        // return
        // else
        //     redis.log(redis.LOG_NOTICE, "da value " .. value)
        //     -- guard failed, return the actually red value
        //     end;
        // let script = redis::Script::new(GUARDED_WRITE_LUA_SCRIPT);
        // script = array_arg(script, guard_address, guard_value);
        // if let Some(byte_array) = guard_value {
        //     // TODO : is cloning sub optimal?
        //     let concatenated = format!("{:?}", byte_array);
        //     println!("Concatenated: {}", concatenated);

        //     script.arg(555).arg(99);
        // }
        // script.arg(78.to_string());
        // script.arg(78.to_string());
        // script.arg(78.to_string());
        // script.arg(78.to_string());

        // for (address, word) in &bindings {
        //     script = array_arg(script, address, Some(*word));
        // }

        // enum VectArg<Address, const WORD_LENGTH: usize> {
        //     Address(Address),
        //     Value(String),
        //     Numb(usize),
        // }

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

        // let mut all_args: Vec<VectArg<Address, WORD_LENGTH>> = vec![
        //     VectArg::Address(guard_address), // can be i32, u32, String, etc.
        //     if let Some(byte_array) = guard_value {
        //         VectArg::Value(format!("{:?}", byte_array))
        //     } else {
        //         VectArg::Value("false".to_string())
        //     }, // String
        //     VectArg::Numb(bindings.len()),
        // ];

        // // Add bindings
        // for (key, value) in bindings {
        //     all_args.push(VectArg::Address(key));
        //     all_args.push(if let Some(byte_array) = guard_value {
        //         VectArg::Value(format!("{:?}", byte_array))
        //     } else {
        //         VectArg::Value("false".to_string())
        //     });
        // }

        let result: Result<Option<Self::Word>, redis::RedisError> =
            script_invocation.invoke(safe_connexion);

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
