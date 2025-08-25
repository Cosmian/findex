// Could we make that implementation independent from Findex? For example:
//
// ```
// struct IndexBatcher<I: Index, ...> {
//     memory: MemoryBatcher,
//     index: I,
// }
// ```

use std::{collections::HashSet, fmt::Debug, hash::Hash};

use cosmian_sse_memories::{ADDRESS_LENGTH, Address, BatchingMemoryADT, MemoryBatcher};

use crate::{Decoder, Encoder, Findex, IndexADT, adt::IndexBatcher, error::BatchFindexError};

// Derive what is free to derive (e.g. Clone...)
// Is this structure thread-safe?
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

    // Why is this comment useful here?
    // Both insert and delete operations make an unbounded number of calls to
    // `guarded_write` on the memory layer.
    async fn batch_insert_or_delete<Keyword>(
        &self,
        entries: Vec<(Keyword, impl Send + IntoIterator<Item = Value>)>,
        is_insert: bool,
    ) -> Result<(), BatchFindexError<BatcherMemory>>
    where
        Keyword: Send + Sync + Hash + Eq,
    {
        // If you must use a for loop, declare your loop variable right before
        // the loop. Maps and iterators do not mix well with asynchronous calls.
        // However, your loop only calls synchronous code. It should therefore
        // be possible to use the map pattern instead:
        //
        // ```
        // let futures = entries.into_iter().map(|entry| {
        //     let index = index.clone();
        //     async move{ ... })
        //  .collect();
        // ```
        //
        // Anyway, you should spawn a task here, using you runtime abstraction.
        let mut futures = Vec::new();
        let memory = MemoryBatcher::new(self.memory.clone(), entries.len());

        for (guard_keyword, bindings) in entries {
            let memory = memory.clone();
            // TBZ: we should be able to create it once and for all: since a
            // Findex instance is thread-safe, we should be able to clone it
            // around.
            //
            // Create a temporary Findex instance
            // using the shared batching layer.
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
                // Once one of the operations succeeds, we should make the
                // buffer smaller.
                memory.unsubscribe().await?;
                Ok::<_, BatchFindexError<_>>(())
            };

            futures.push(future);
        }

        // TBZ: do not rephrase your code!
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

    // Can't you make your insert_or_delete operation generic enough to fit
    // this? This is essentially the exact same code if you remove the specific
    // nature of the function and the arguments on which it is called.
    async fn batch_search(
        &self,
        keywords: Vec<&Keyword>,
    ) -> Result<Vec<HashSet<Value>>, Self::Error> {
        let memory = MemoryBatcher::new(self.memory.clone(), keywords.len());

        let mut futures = Vec::new();
        for keyword in keywords {
            let memory = memory.clone();
            let findex = Findex::<WORD_LENGTH, Value, EncodingError, _>::new(
                memory,
                self.encode,
                self.decode,
            );

            let future = async move { findex.search(keyword).await };
            futures.push(future);
        }

        futures::future::try_join_all(futures)
            .await
            .map_err(|e| BatchFindexError::Findex(e))
    }
}

// TBZ: make this a module doc using //! ?
//
// Generic, runtime-agnostic IndexBatcher tests should be defined the same way
// generic, runtime-agnostic Vector or Index tests were defined.
//
// The underlying tests assume the existence of a `Findex` implementation that
// is correct The testing strategy for each function is to use the `Findex`
// implementation to perform the same operations and compare the results with
// the `BatcherFindex` implementation.
#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cosmian_crypto_core::define_byte_type;
    use cosmian_sse_memories::{ADDRESS_LENGTH, InMemory};

    use super::*;
    use crate::{Findex, IndexADT, dummy_decode, dummy_encode};

    // Your type Byte is 8-byte long...
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
