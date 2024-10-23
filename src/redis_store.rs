use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    hash::Hash,
    marker::PhantomData,
    panic,
    sync::{Arc, Mutex},
};

use redis::{Commands, ConnectionInfo, FromRedisValue, ToRedisArgs};

use crate::MemoryADT;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisMemoryError;

impl Display for RedisMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Memory Error")
    }
}

impl std::error::Error for RedisMemoryError {}

// TODO : debug
#[derive(Clone)]
pub struct RedisMemory<Address, Value>
where
    Address: Hash + Eq,
    Value: Clone + Eq,
{
    connexion: Arc<Mutex<redis::Connection>>,
    _marker: PhantomData<(Address, Value)>,
}

impl<Address: Hash + Eq + Debug, Value: Clone + Eq + Debug> Default
    for RedisMemory<Address, Value>
{
    fn default() -> Self {
        Self {
            connexion: match redis::Client::open("redis://127.0.0.1/") {
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

impl<
    Address: Send + Sync + Hash + Eq + Debug + redis::ToRedisArgs,
    Value: Send + Sync + Clone + Eq + Debug + FromRedisValue + ToRedisArgs,
> MemoryADT for RedisMemory<Address, Value>
{
    type Address = Address;
    type Error = RedisMemoryError;
    type Word = Value;

    async fn batch_read(&self, a: Vec<Address>) -> Result<Vec<Option<Value>>, Self::Error> {
        let safe_connexion = &mut *self.connexion.lock().expect("Poisoned lock.");
        let result: Vec<Option<Value>> = a
            .iter()
            .map(|k| match safe_connexion.get::<&Address, Value>(k) {
                Ok(val) => Some(val),
                Err(_e) => None,
            })
            .collect();
        Ok(result)
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let safe_connexion = &mut *self.connexion.lock().expect("Poisoned lock.");
        let (a, old) = guard;

        let cur = match safe_connexion.get(&a) {
            Ok(val) => val,
            Err(e) => {
                panic!("Error reading from redis: {:?}", e);
            }
        };
        if old == cur {
            for (k, v) in bindings {
                let _: () = match safe_connexion.set(k, v) {
                    Ok(res) => res,
                    Err(e) => {
                        panic!("sss {:?}", e);
                    }
                };
            }
        }
        Ok(cur)
    }
}

#[cfg(test)]
mod tests {

    // use futures::executor::block_on;

    // use crate::MemoryADT;

    // use super::InMemory;

    // /// Ensures a transaction can express a vector push operation:
    // /// - the counter is correctly incremented and all values are written;
    // /// - using the wrong value in the guard fails the operation and returns
    // the current value. #[test]
    // fn test_vector_push() {
    //     let memory = InMemory::<u8, u8>::default();

    //     assert_eq!(
    //         block_on(memory.guarded_write((0, None), vec![(0, 2), (1, 1), (2,
    // 1)])).unwrap(),         None
    //     );
    //     assert_eq!(
    //         block_on(memory.guarded_write((0, None), vec![(0, 4), (3, 2), (4,
    // 2)])).unwrap(),         Some(2)
    //     );
    //     assert_eq!(
    //         block_on(memory.guarded_write((0, Some(2)), vec![(0, 4), (3, 3),
    // (4, 3)])).unwrap(),         Some(2)
    //     );
    //     assert_eq!(
    //         vec![Some(1), Some(1), Some(3), Some(3)],
    //         block_on(memory.batch_read(vec![1, 2, 3, 4])).unwrap(),
    //     )
    // }
}
