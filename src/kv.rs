use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    hash::Hash,
    sync::{Arc, Mutex},
};

use crate::stm::Stm;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryError;

impl Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Memory Error")
    }
}

impl std::error::Error for MemoryError {}

#[derive(Clone, Debug, Default)]
pub struct KvStore<Address: Hash + Eq, Value>(Arc<Mutex<HashMap<Address, Value>>>);

impl<Address: Hash + Eq + Debug, Value: Clone + Eq + Debug> Stm for KvStore<Address, Value> {
    type Address = Address;

    type Word = Value;

    type Error = MemoryError;

    async fn batch_read(&self, a: Vec<Address>) -> Result<Vec<Option<Value>>, Self::Error> {
        let store = &mut *self.0.lock().expect("poisoned lock");
        Ok(a.into_iter().map(|k| store.get(&k).cloned()).collect())
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let store = &mut *self.0.lock().expect("poisoned lock");
        let (a, old) = guard;
        let cur = store.get(&a).cloned();
        if old == cur {
            for (k, v) in bindings {
                store.insert(k, v);
            }
        }
        Ok(cur)
    }
}

#[cfg(test)]
mod tests {

    use futures::executor::block_on;

    use crate::Stm;

    use super::KvStore;

    /// Ensures a transaction can express an vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns the current value.
    #[test]
    fn test_vector_push() {
        let kv = KvStore::<u8, u8>::default();

        assert_eq!(
            block_on(kv.guarded_write((0, None), vec![(0, 2), (1, 1), (2, 1)])).unwrap(),
            None
        );
        assert_eq!(
            block_on(kv.guarded_write((0, None), vec![(0, 4), (3, 2), (4, 2)])).unwrap(),
            Some(2)
        );
        assert_eq!(
            block_on(kv.guarded_write((0, Some(2)), vec![(0, 4), (3, 3), (4, 3)])).unwrap(),
            Some(2)
        );
        assert_eq!(
            vec![Some(1), Some(1), Some(3), Some(3)],
            block_on(kv.batch_read(vec![1, 2, 3, 4])).unwrap(),
        )
    }
}
