//! A thread-safe implementation of the `MemoryADT` trait based on a `HashMap`.

use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    hash::Hash,
    sync::{Arc, Mutex},
};

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
    pub fn with_capacity(c: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::with_capacity(c))),
        }
    }

    pub fn clear(&self) {
        self.inner.lock().expect("poisoned lock").clear();
    }
}

impl<Address: Send + Hash + Eq + Debug, Value: Send + Clone + Eq + Debug> MemoryADT
    for InMemory<Address, Value>
{
    type Address = Address;

    type Word = Value;

    type Error = MemoryError;

    async fn batch_read(&self, addresses: Vec<Address>) -> Result<Vec<Option<Value>>, Self::Error> {
        let store = self.inner.lock().expect("poisoned lock");
        Ok(addresses.iter().map(|k| store.get(k).cloned()).collect())
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

    use super::InMemory;
    use crate::test_utils::{
        gen_seed, test_guarded_write_concurrent, test_rw_same_address, test_single_write_and_read,
        test_wrong_guard,
    };

    #[tokio::test]
    async fn test_sequential_read_write() {
        let memory = InMemory::<[u8; 16], [u8; 16]>::default();
        test_single_write_and_read(&memory, gen_seed()).await;
    }

    #[tokio::test]
    async fn test_sequential_wrong_guard() {
        let memory = InMemory::<[u8; 16], [u8; 16]>::default();
        test_wrong_guard(&memory, gen_seed()).await;
    }

    #[tokio::test]
    async fn test_sequential_rw_same_address() {
        let memory = InMemory::<[u8; 16], [u8; 16]>::default();
        test_rw_same_address(&memory, gen_seed()).await;
    }

    #[tokio::test]
    async fn test_concurrent_read_write() {
        let memory = InMemory::<[u8; 16], [u8; 16]>::default();
        test_guarded_write_concurrent(&memory, gen_seed(), None).await;
    }
}
