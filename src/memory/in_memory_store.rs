use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    sync::{Arc, Mutex},
};

#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

use crate::{Address, MemoryADT, Word};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryError;

impl Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Memory Error")
    }
}

impl std::error::Error for MemoryError {}

#[derive(Clone, Debug)]
pub struct InMemory<const WORD_LENGTH: usize> {
    inner: Arc<Mutex<HashMap<Address, Word<WORD_LENGTH>>>>,
}

impl<const WORD_LENGTH: usize> Default for InMemory<WORD_LENGTH> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<const WORD_LENGTH: usize> InMemory<WORD_LENGTH> {
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

impl<const WORD_LENGTH: usize> MemoryADT<WORD_LENGTH> for InMemory<WORD_LENGTH> {
    type Error = MemoryError;

    async fn batch_read(
        &self,
        a: Vec<Address>,
    ) -> Result<Vec<Option<Word<WORD_LENGTH>>>, Self::Error> {
        let store = self.inner.lock().expect("poisoned lock");
        Ok(a.iter().map(|k| store.get(k).cloned()).collect())
    }

    async fn guarded_write(
        &self,
        guard: (Address, Option<Word<WORD_LENGTH>>),
        bindings: Vec<(Address, Word<WORD_LENGTH>)>,
    ) -> Result<Option<Word<WORD_LENGTH>>, Self::Error> {
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
impl<const WORD_LENGTH: usize> IntoIterator for InMemory<WORD_LENGTH> {
    type Item = (Address, Word<WORD_LENGTH>);

    type IntoIter = <HashMap<Address, Word<WORD_LENGTH>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.inner
            .lock()
            .expect("poisoned lock")
            .clone()
            .into_iter()
    }
}

#[cfg(feature = "serialization")]
impl<const WORD_LENGTH: usize> Serialize for InMemory<WORD_LENGTH> {
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

#[cfg(feature = "serialization")]
impl<'de, const WORD_LENGTH: usize> Deserialize<'de> for InMemory<WORD_LENGTH> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        HashMap::deserialize(deserializer).map(|inner| Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }
}

#[cfg(test)]
mod tests {

    use futures::executor::block_on;

    use crate::{Address, MemoryADT, Word, address::ADDRESS_LENGTH};

    use super::InMemory;

    const WORD_LENGTH: usize = 16;

    /// Ensures a transaction can express a vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns the current value.
    #[test]
    fn test_vector_push() {
        let memory = InMemory::<WORD_LENGTH>::default();

        let a0 = Address::from([0; ADDRESS_LENGTH]);
        let a1 = Address::from([1; ADDRESS_LENGTH]);
        let a2 = Address::from([2; ADDRESS_LENGTH]);
        let a3 = Address::from([3; ADDRESS_LENGTH]);
        let a4 = Address::from([4; ADDRESS_LENGTH]);

        let w1 = Word::from([1; WORD_LENGTH]);
        let w2 = Word::from([2; WORD_LENGTH]);
        let w3 = Word::from([3; WORD_LENGTH]);
        let w4 = Word::from([4; WORD_LENGTH]);

        assert_eq!(
            block_on(memory.guarded_write((a0.clone(), None), vec![
                (a0.clone(), w2.clone()),
                (a1.clone(), w1.clone()),
                (a2.clone(), w1.clone())
            ]))
            .unwrap(),
            None
        );
        assert_eq!(
            block_on(memory.guarded_write((a0.clone(), None), vec![
                (a0.clone(), w4.clone()),
                (a3.clone(), w2.clone()),
                (a4.clone(), w2.clone())
            ]))
            .unwrap(),
            Some(w2.clone())
        );
        assert_eq!(
            block_on(memory.guarded_write((a0.clone(), Some(w2.clone())), vec![
                (a0, w4),
                (a3.clone(), w3.clone()),
                (a4.clone(), w3.clone())
            ]))
            .unwrap(),
            Some(w2)
        );
        assert_eq!(
            vec![Some(w1.clone()), Some(w1), Some(w3.clone()), Some(w3)],
            block_on(memory.batch_read(vec![a1, a2, a3, a4])).unwrap(),
        )
    }

    #[cfg(feature = "serialization")]
    #[test]
    fn test_in_memory_serialization() {
        use crate::{Address, Word};

        let mem = InMemory::<WORD_LENGTH>::default();
        block_on(mem.guarded_write((Address::default(), None), vec![
            (Address::default() + 1, Word::default()),
            (Address::default() + 2, Word::default()),
        ]))
        .unwrap();

        let bytes = bincode::serialize(&mem).unwrap();
        let res = bincode::deserialize::<InMemory<WORD_LENGTH>>(&bytes).unwrap();

        let mut bindings_1 = mem.into_iter().collect::<Vec<_>>();
        bindings_1.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));

        let mut bindings_2 = res.into_iter().collect::<Vec<_>>();
        bindings_2.sort_by(|(k1, _), (k2, _)| k1.cmp(k2));

        assert_eq!(bindings_1, bindings_2);
    }
}
