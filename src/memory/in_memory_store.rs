use std::{
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    sync::{Arc, Mutex},
};

use super::error::MemoryError;
use crate::MemoryADT;

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

impl<Address: Send + Sync + Hash + Eq + Debug, Value: Send + Sync + Clone + Eq + Debug> MemoryADT
    for InMemory<Address, Value>
{
    type Address = Address;
    type Error = MemoryError;
    type Word = Value;

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
    type IntoIter = <HashMap<Address, Value> as IntoIterator>::IntoIter;
    type Item = (Address, Value);

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

    #[cfg(feature = "test-utils")]
    use crate::{
        memory::in_memory_store, test_guarded_write_concurrent, test_single_write_and_read,
        test_wrong_guard,
    };

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn test_sequential_read_write() {
        let memory = in_memory_store::InMemory::<[u8; 16], [u8; 16]>::default();
        test_single_write_and_read(&memory, rand::random()).await;
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn test_sequential_wrong_guard() {
        let memory = in_memory_store::InMemory::<[u8; 16], [u8; 16]>::default();
        test_wrong_guard(&memory, rand::random()).await;
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn test_concurrent_read_write() {
        let memory = in_memory_store::InMemory::<[u8; 16], [u8; 16]>::default();
        test_guarded_write_concurrent(&memory, rand::random()).await;
    }
}
