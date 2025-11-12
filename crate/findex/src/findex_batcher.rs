use std::{collections::HashSet, fmt::Debug, hash::Hash, num::NonZero};

use cosmian_sse_memories::{ADDRESS_LENGTH, Address, BatchingMemoryADT, MemoryBatcher};

use crate::{Decoder, Encoder, Findex, IndexADT, adt::IndexBatcher, error::BatchFindexError};

#[derive(Debug)]
pub struct FindexBatcher<
    const WORD_LENGTH: usize,
    Value: Send + Hash + Eq,
    EncodingError: Send + Debug,
    BatcherMemory: Clone + Send + BatchingMemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> {
    memory: BatcherMemory,
    encode: Encoder<Value, BatcherMemory::Word, EncodingError>,
    decode: Decoder<Value, BatcherMemory::Word, EncodingError>,
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
            encode,
            decode,
        }
    }

    async fn batch_insert_or_delete<Keyword, Bindings, Entries>(
        &self,
        entries: Entries,
        is_insert: bool,
    ) -> Result<(), BatchFindexError<BatcherMemory>>
    where
        Keyword: Send + Sync + Hash + Eq,
        Bindings: Send + IntoIterator<Item = Value>,
        Entries: IntoIterator<Item = (Keyword, Bindings)> + Send,
        Entries::IntoIter: ExactSizeIterator,
    {
        let entries = entries.into_iter();
        let n = entries.len();
        let mut futures = Vec::with_capacity(n);
        let memory = MemoryBatcher::new(
            self.memory.clone(),
            NonZero::new(n)
                .ok_or_else(|| BatchFindexError::Other("Batch size can not be zero".to_owned()))?,
        );

        for (guard_keyword, bindings) in entries {
            let memory = memory.clone();
            // Create a temporary Findex instance using the shared batching layer.
            let findex = Findex::<WORD_LENGTH, Value, EncodingError, _>::new(
                memory.clone(),
                self.encode,
                self.decode,
            );

            let future = async move {
                if is_insert {
                    findex.insert(guard_keyword, bindings).await
                } else {
                    findex.delete(guard_keyword, bindings).await
                }?;
                // Within findex, insert/delete operations may perform a variable number of
                // memory writes. This requires explicit `unsubscribe()` calls
                // to adjust the expected buffer size once one of the operations succeeds.
                memory.unsubscribe().await?;
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
    BatchingMemoryLayer: Debug
        + Send
        + Sync
        + Clone
        + BatchingMemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> IndexBatcher<Keyword, Value>
    for FindexBatcher<WORD_LENGTH, Value, EncodingError, BatchingMemoryLayer>
{
    type Error = BatchFindexError<BatchingMemoryLayer>;

    async fn batch_insert<Bindings, Entries>(&self, entries: Entries) -> Result<(), Self::Error>
    where
        Bindings: Send + IntoIterator<Item = Value>,
        Entries: Send + IntoIterator<Item = (Keyword, Bindings)>,
        Entries::IntoIter: ExactSizeIterator,
    {
        self.batch_insert_or_delete(entries, true).await
    }

    async fn batch_delete<Bindings, Entries>(&self, entries: Entries) -> Result<(), Self::Error>
    where
        Bindings: Send + IntoIterator<Item = Value>,
        Entries: Send + IntoIterator<Item = (Keyword, Bindings)>,
        Entries::IntoIter: ExactSizeIterator,
    {
        self.batch_insert_or_delete(entries, false).await
    }

    async fn batch_search(
        &self,
        keywords: Vec<&Keyword>,
    ) -> Result<Vec<HashSet<Value>>, Self::Error> {
        let n = keywords.len();
        let mut futures = Vec::with_capacity(n);
        let memory = MemoryBatcher::new(
            self.memory.clone(),
            NonZero::new(n)
                .ok_or_else(|| BatchFindexError::Other("Batch size can not be zero".to_owned()))?,
        );

        for keyword in keywords {
            let memory = memory.clone();
            let findex = Findex::<WORD_LENGTH, Value, EncodingError, _>::new(
                memory,
                self.encode,
                self.decode,
            );
            // Search operations do not require calling `unsubscribe()` on the memory
            // batcher. This is because all Findex search operations perform the
            // same deterministic number of memory read operations.
            // Specifically, each (safe) Findex search completes after
            // performing exactly two reads.
            let future = async move { findex.search(keyword).await };
            futures.push(future);
        }

        futures::future::try_join_all(futures)
            .await
            .map_err(|e| BatchFindexError::Findex(e))
    }
}

// These tests implement dual testing against the base Findex implementation.
#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cosmian_crypto_core::define_byte_type;
    use cosmian_sse_memories::{ADDRESS_LENGTH, InMemory};

    use super::*;
    use crate::{Findex, IndexADT, dummy_decode, dummy_encode};

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
    async fn test_batch_insert_and_delete() {
        let trivial_memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();

        // Initial data for insertion
        let cat_bindings = vec![
            Value::try_from(1).unwrap(),
            Value::try_from(2).unwrap(),
            Value::try_from(3).unwrap(),
            Value::try_from(7).unwrap(),
        ];
        let dog_bindings = vec![
            Value::try_from(4).unwrap(),
            Value::try_from(5).unwrap(),
            Value::try_from(6).unwrap(),
        ];

        // Insert using normal findex
        let findex = Findex::new(
            trivial_memory.clone(),
            dummy_encode::<WORD_LENGTH, Value>,
            dummy_decode,
        );

        findex
            .insert("cat".to_string(), cat_bindings.clone())
            .await
            .unwrap();
        findex
            .insert("dog".to_string(), dog_bindings.clone())
            .await
            .unwrap();

        // Create a `findex_batcher` instance
        let findex_batcher = FindexBatcher::<WORD_LENGTH, Value, _, _>::new(
            trivial_memory.clone(),
            dummy_encode,
            dummy_decode,
        );

        // Test batch delete
        let deletion_entries = vec![
            (
                "cat".to_string(),
                vec![Value::try_from(1).unwrap(), Value::try_from(3).unwrap()], // Partial deletion
            ),
            ("dog".to_string(), dog_bindings), // Complete deletion
        ];

        findex_batcher.batch_delete(deletion_entries).await.unwrap();

        // Verify deletions using normal findex
        let cat_result_after_delete = findex.search(&"cat".to_string()).await.unwrap();
        let dog_result_after_delete = findex.search(&"dog".to_string()).await.unwrap();

        let expected_cat = vec![
            Value::try_from(2).unwrap(), // 1 and 3 removed, 2 and 7 remain
            Value::try_from(7).unwrap(),
        ]
        .into_iter()
        .collect::<HashSet<_>>();
        let expected_dog = HashSet::new(); // All dog bindings removed

        assert_eq!(cat_result_after_delete, expected_cat);
        assert_eq!(dog_result_after_delete, expected_dog);

        // Test batch insert
        let insert_entries = vec![(
            "dog".to_string(),
            vec![Value::try_from(8).unwrap(), Value::try_from(9).unwrap()],
        )];

        findex_batcher.batch_insert(insert_entries).await.unwrap();

        // Verify insertions using normal findex
        let new_dog_results = findex.search(&"dog".to_string()).await.unwrap();

        let expected_dog = vec![Value::try_from(8).unwrap(), Value::try_from(9).unwrap()]
            .into_iter()
            .collect::<HashSet<_>>();

        assert_eq!(new_dog_results, expected_dog);
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

        let findex_batcher = FindexBatcher::<WORD_LENGTH, Value, _, _>::new(
            trivial_memory.clone(),
            dummy_encode,
            dummy_decode,
        );

        let key1 = "cat".to_string();
        let key2 = "dog".to_string();
        // Perform batch search
        let batch_search_results = findex_batcher
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
