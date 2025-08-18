use crate::adt::IndexBatcher;
use crate::error::BatchFindexError;
use crate::{Decoder, Encoder, Findex, IndexADT};
use cosmian_sse_memories::{ADDRESS_LENGTH, Address, BatchingMemoryADT, MemoryBatcher};
use std::sync::atomic::AtomicUsize;
use std::{collections::HashSet, fmt::Debug, hash::Hash, sync::Arc};

#[derive(Debug)]
pub struct FindexBatcher<
    const WORD_LENGTH: usize,
    Value: Send + Hash + Eq,
    EncodingError: Send + Debug,
    BatcherMemory: Clone + Send + BatchingMemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> {
    memory: BatcherMemory,
    encode: Arc<Encoder<Value, BatcherMemory::Word, EncodingError>>,
    decode: Arc<Decoder<Value, BatcherMemory::Word, EncodingError>>,
}

impl<
    const WORD_LENGTH: usize,
    Value: Send + Hash + Eq,
    BatcherMemory: Debug
        + Send
        + Sync
        + Clone
        + BatchingMemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
    EncodingError: Send + Debug,
> FindexBatcher<WORD_LENGTH, Value, EncodingError, BatcherMemory>
{
    pub fn new(
        memory: BatcherMemory,
        encode: Encoder<Value, BatcherMemory::Word, EncodingError>,
        decode: Decoder<Value, BatcherMemory::Word, EncodingError>,
    ) -> Self {
        Self {
            memory,
            encode: Arc::new(encode),
            decode: Arc::new(decode),
        }
    }

    // Insert or delete are both an unbounded number of calls to `guarded_write` on the memory layer.
    async fn batch_insert_or_delete<Keyword>(
        &self,
        entries: Vec<(Keyword, impl Send + IntoIterator<Item = Value>)>,
        is_insert: bool,
    ) -> Result<(), BatchFindexError<BatcherMemory>>
    where
        Keyword: Send + Sync + Hash + Eq,
    {
        let mut futures = Vec::new();
        let buffered_memory = Arc::new(MemoryBatcher::new_writer(
            self.memory.clone(),
            AtomicUsize::new(entries.len()),
        ));

        for (guard_keyword, bindings) in entries {
            let memory_arc = buffered_memory.clone(); // TODO
            // Create a temporary Findex instance using the shared batching layer
            let findex = Findex::<WORD_LENGTH, Value, EncodingError, _>::new(
                // This (cheap) Arc clone is necessary because `decrement_capacity` is called
                // below and needs to be able to access the Arc.
                memory_arc.clone(),
                *self.encode,
                *self.decode,
            );

            let future = async move {
                if is_insert {
                    findex.insert(guard_keyword, bindings).await
                } else {
                    findex.delete(guard_keyword, bindings).await
                }?;
                // Once one of the operations succeeds, we should make the buffer smaller.
                memory_arc.decrement_capacity().await?;
                Ok::<_, BatchFindexError<_>>(())
            };

            futures.push(future);
        }

        // Execute all futures concurrently and collect results.
        futures::future::try_join_all(futures).await?;

        Ok(())
    }
}

impl<
    const WORD_LENGTH: usize,
    Keyword: Send + Sync + Hash + Eq,
    Value: Send + Hash + Eq,
    EncodingError: Send + Debug,
    BatcherMemory: Debug
        + Send
        + Sync
        + Clone
        + BatchingMemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> IndexBatcher<Keyword, Value> for FindexBatcher<WORD_LENGTH, Value, EncodingError, BatcherMemory>
{
    type Error = BatchFindexError<BatcherMemory>;

    async fn batch_insert(
        &self,
        entries: Vec<(Keyword, impl Sync + Send + IntoIterator<Item = Value>)>,
    ) -> Result<(), Self::Error> {
        self.batch_insert_or_delete(entries, true).await
    }

    async fn batch_delete(
        &self,
        entries: Vec<(Keyword, impl Sync + Send + IntoIterator<Item = Value>)>,
    ) -> Result<(), Self::Error> {
        self.batch_insert_or_delete(entries, false).await
    }

    async fn batch_search(
        &self,
        keywords: Vec<&Keyword>,
    ) -> Result<Vec<HashSet<Value>>, Self::Error> {
        let mut futures = Vec::new();
        let buffered_memory = Arc::new(MemoryBatcher::new_reader(
            self.memory.clone(),
            AtomicUsize::new(keywords.len()),
        ));

        for keyword in keywords {
            let buffered_memory = buffered_memory.clone();
            // Create a temporary Findex instance using the shared batching layer.
            let findex = Findex::<WORD_LENGTH, Value, EncodingError, _>::new(
                buffered_memory,
                *self.encode,
                *self.decode,
            );

            let future = async move { findex.search(keyword).await };
            futures.push(future);
        }

        // Execute all futures concurrently and collect results.
        futures::future::try_join_all(futures)
            .await
            .map_err(|e| BatchFindexError::Findex(e))
    }
}

// The underlying tests assume the existence of a `Findex` implementation that is correct
// The testing strategy for each function is to use the `Findex` implementation to perform the same operations
// and compare the results with the `BatcherFindex` implementation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Findex, IndexADT, dummy_decode, dummy_encode};
    use cosmian_crypto_core::define_byte_type;
    use cosmian_sse_memories::{ADDRESS_LENGTH, InMemory};
    use std::collections::HashSet;

    type Value = Bytes<8>;
    define_byte_type!(Bytes);

    impl<const LENGTH: usize> TryFrom<usize> for Bytes<LENGTH> {
        type Error = String;
        fn try_from(value: usize) -> Result<Self, Self::Error> {
            Self::try_from(value.to_be_bytes().as_slice()).map_err(|e| e.to_string())
        }
    }

    const WORD_LENGTH: usize = 16;

    #[tokio::test]
    async fn test_batch_insert() {
        let trivial_memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();

        let batcher_findex = FindexBatcher::<WORD_LENGTH, Value, _, _>::new(
            trivial_memory.clone(),
            dummy_encode,
            dummy_decode,
        );

        let cat_bindings = vec![
            Value::try_from(1).unwrap(),
            Value::try_from(2).unwrap(),
            Value::try_from(3).unwrap(),
        ];
        let dog_bindings = vec![
            Value::try_from(4).unwrap(),
            Value::try_from(5).unwrap(),
            Value::try_from(6).unwrap(),
        ];

        // Batch insert multiple entries.
        let entries = vec![
            ("cat".to_string(), cat_bindings.clone()),
            ("dog".to_string(), dog_bindings.clone()),
        ];

        batcher_findex.batch_insert(entries).await.unwrap();

        // instantiate a (non batched) Findex to verify the results.
        let findex = Findex::new(
            trivial_memory.clone(),
            dummy_encode::<WORD_LENGTH, Value>,
            dummy_decode,
        );

        let cat_result = findex.search(&"cat".to_string()).await.unwrap();
        assert_eq!(cat_result, cat_bindings.into_iter().collect::<HashSet<_>>());

        let dog_result = findex.search(&"dog".to_string()).await.unwrap();
        assert_eq!(dog_result, dog_bindings.into_iter().collect::<HashSet<_>>());
    }

    #[tokio::test]
    async fn test_batch_delete() {
        let trivial_memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();

        // First, populate the memory with initial data using regular Findex.
        let findex = Findex::new(
            trivial_memory.clone(),
            dummy_encode::<WORD_LENGTH, Value>,
            dummy_decode,
        );

        let cat_bindings = vec![
            Value::try_from(1).unwrap(),
            Value::try_from(3).unwrap(),
            Value::try_from(5).unwrap(),
            Value::try_from(7).unwrap(),
        ];
        let dog_bindings = vec![
            Value::try_from(0).unwrap(),
            Value::try_from(2).unwrap(),
            Value::try_from(4).unwrap(),
            Value::try_from(6).unwrap(),
        ];

        findex
            .insert("cat".to_string(), cat_bindings.clone())
            .await
            .unwrap();
        findex
            .insert("dog".to_string(), dog_bindings.clone())
            .await
            .unwrap();

        // Create BatcherFindex for deletion operations.
        let batcher_findex = FindexBatcher::<WORD_LENGTH, Value, _, _>::new(
            trivial_memory.clone(),
            dummy_encode,
            dummy_decode,
        );

        let delete_entries = vec![
            (
                "cat".to_string(),
                vec![Value::try_from(1).unwrap(), Value::try_from(5).unwrap()],
            ),
            ("dog".to_string(), dog_bindings), // Remove all dog bindings.
        ];

        // Perform batch delete.
        batcher_findex.batch_delete(delete_entries).await.unwrap();

        // Verify deletions were performed using a regular findex instance.
        let cat_result = findex.search(&"cat".to_string()).await.unwrap();
        let dog_result = findex.search(&"dog".to_string()).await.unwrap();

        let expected_cat = vec![
            Value::try_from(3).unwrap(), // 1 and 5 removed, 3 and 7 remain.
            Value::try_from(7).unwrap(),
        ]
        .into_iter()
        .collect::<HashSet<_>>();
        let expected_dog = HashSet::new(); // all of the dog bindings are removed.

        assert_eq!(cat_result, expected_cat);
        assert_eq!(dog_result, expected_dog);
    }

    #[tokio::test]
    async fn test_batch_search() {
        let trivial_memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();

        let findex = Findex::new(
            trivial_memory.clone(),
            dummy_encode::<WORD_LENGTH, Value>,
            dummy_decode,
        );
        let cat_bindings = [
            Value::try_from(1).unwrap(),
            Value::try_from(3).unwrap(),
            Value::try_from(5).unwrap(),
        ];
        let dog_bindings = [
            Value::try_from(0).unwrap(),
            Value::try_from(2).unwrap(),
            Value::try_from(4).unwrap(),
        ];
        findex
            .insert("cat".to_string(), cat_bindings.clone())
            .await
            .unwrap();
        findex
            .insert("dog".to_string(), dog_bindings.clone())
            .await
            .unwrap();

        let batcher_findex = FindexBatcher::<WORD_LENGTH, Value, _, _>::new(
            trivial_memory.clone(),
            dummy_encode,
            dummy_decode,
        );

        let key1 = "cat".to_string();
        let key2 = "dog".to_string();
        // Perform batch search
        let batch_search_results = batcher_findex
            .batch_search(vec![&key1, &key2])
            .await
            .unwrap();

        assert_eq!(
            batch_search_results,
            vec![
                cat_bindings.iter().cloned().collect::<HashSet<_>>(),
                dog_bindings.iter().cloned().collect::<HashSet<_>>()
            ]
        );
    }
}
