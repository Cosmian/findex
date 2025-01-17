use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    hash::Hash,
    sync::{Arc, Mutex},
};

#[cfg(feature = "bench")]
use serde::{Deserialize, Serialize};

use crate::MemoryADT;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryError;

impl Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Memory Error")
    }
}

impl std::error::Error for MemoryError {}

#[derive(Clone, Debug)]
pub struct InMemory<Address: Hash + Eq, Value> {
    inner: Arc<Mutex<HashMap<Address, Value>>>,
}

impl<Address: Hash + Eq + Debug, Value: Clone + Eq + Debug> Default for InMemory<Address, Value> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<Address: Hash + Eq + Debug, Value: Clone + Eq + Debug> InMemory<Address, Value> {
    #[cfg(feature = "bench")]
    pub fn with_capacity(c: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::with_capacity(c))),
        }
    }

    #[cfg(any(test, feature = "bench"))]
    pub fn clear(&self) {
        self.inner.lock().expect("poisoned lock").clear();
    }
}

#[cfg(feature = "bench")]
impl<Address: Hash + Eq + Debug + Serialize, Value: Clone + Eq + Debug + Serialize> Serialize
    for InMemory<Address, Value>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.inner
            .lock()
            .expect("poisoned lock")
            .serialize(serializer)
    }
}

#[cfg(feature = "bench")]
impl<
    'de,
    Address: Hash + Eq + Debug + Deserialize<'de>,
    Value: Clone + Eq + Debug + Deserialize<'de>,
> Deserialize<'de> for InMemory<Address, Value>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        HashMap::deserialize(deserializer).map(|inner| Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }
}

impl<Address: Send + Sync + Hash + Eq + Debug, Value: Send + Sync + Clone + Eq + Debug> MemoryADT
    for InMemory<Address, Value>
{
    type Address = Address;

    type Word = Value;

    type Error = MemoryError;

    async fn batch_read(&self, a: Vec<Address>) -> Result<Vec<Option<Value>>, Self::Error> {
        let store = self.inner.lock().expect("poisoned lock");
        Ok(a.iter().map(|k| store.get(k).cloned()).collect())
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let store = &mut *self.inner.lock().expect("poisoned lock");
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

#[cfg(feature = "bench")]
impl<Address: Hash + Eq + Debug + Clone, Value: Clone + Eq + Debug> IntoIterator
    for InMemory<Address, Value>
{
    type Item = (Address, Value);

    type IntoIter = <HashMap<Address, Value> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.inner
            .lock()
            .expect("poisoned lock")
            .clone()
            .into_iter()
    }
}

#[cfg(test)]
mod tests {

    use futures::executor::block_on;

    use crate::MemoryADT;

    use super::InMemory;

    /// Ensures a transaction can express a vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns the current value.
    #[test]
    fn test_vector_push() {
        let memory = InMemory::<u8, u8>::default();

        assert_eq!(
            block_on(memory.guarded_write((0, None), vec![(0, 2), (1, 1), (2, 1)])).unwrap(),
            None
        );
        assert_eq!(
            block_on(memory.guarded_write((0, None), vec![(0, 4), (3, 2), (4, 2)])).unwrap(),
            Some(2)
        );
        assert_eq!(
            block_on(memory.guarded_write((0, Some(2)), vec![(0, 4), (3, 3), (4, 3)])).unwrap(),
            Some(2)
        );
        assert_eq!(
            vec![Some(1), Some(1), Some(3), Some(3)],
            block_on(memory.batch_read(vec![1, 2, 3, 4])).unwrap(),
        )
    }
}
