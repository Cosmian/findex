use crate::adt::{BatcherSSEADT, BatchingMemoryADT};
use crate::error::BatchFindexError;
use crate::memory::MemoryBatcher;
use crate::{ADDRESS_LENGTH, Address, Decoder, Encoder, Error, Findex, IndexADT};
use std::sync::atomic::AtomicUsize;
use std::{collections::HashSet, fmt::Debug, hash::Hash, sync::Arc};
// TODO : should all of these be sync ?

#[derive(Debug)]
pub struct BatcherFindex<
    const WORD_LENGTH: usize,
    Value: Send + Sync + Hash + Eq,
    EncodingError: Send + Sync + Debug,
    BatcherMemory: Clone
        + Send
        + Sync
        + BatchingMemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> {
    memory: BatcherMemory,
    encode: Arc<Encoder<Value, BatcherMemory::Word, EncodingError>>,
    decode: Arc<Decoder<Value, BatcherMemory::Word, EncodingError>>,
}

impl<
    const WORD_LENGTH: usize,
    Value: Send + Sync + Hash + Eq,
    BatcherMemory: Debug
        + Send
        + Sync
        + Clone
        + BatchingMemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
    EncodingError: Send + Sync + Debug + std::error::Error,
> BatcherFindex<WORD_LENGTH, Value, EncodingError, BatcherMemory>
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
        entries: Vec<(Keyword, impl Sync + Send + IntoIterator<Item = Value>)>,
        is_insert: bool,
    ) -> Result<(), BatchFindexError<BatcherMemory>>
    where
        Keyword: Send + Sync + Hash + Eq,
    {
        let mut search_futures = Vec::new();
        let n = entries.len();
        let buffered_memory = Arc::new(MemoryBatcher::new_writer(
            self.memory.clone(),
            AtomicUsize::new(n),
        ));

        for (guard_keyword, bindings) in entries {
            let memory_arc = buffered_memory.clone();
            let future = async move {
                // Create a temporary Findex instance using the shared batching layer
                let findex: Findex<
                    WORD_LENGTH,
                    Value,
                    EncodingError,
                    Arc<MemoryBatcher<BatcherMemory>>,
                > = Findex::<WORD_LENGTH, Value, EncodingError, _>::new(
                    // this (cheap) Arc cline is necessary because `decrement_capacity` is called
                    // below and needs to be able to access the Arc
                    memory_arc.clone(),
                    *self.encode,
                    *self.decode,
                );

                let result = if is_insert {
                    findex.insert(guard_keyword, bindings).await
                } else {
                    findex.delete(guard_keyword, bindings).await
                };

                // Convert Findex error to BatchingLayerError manually if needed
                if let Err(findex_err) = result {
                    return Err(BatchFindexError::FindexError(findex_err));
                }
                // once one of the operations succeeds, we should make the buffer smaller
                memory_arc.decrement_capacity()?;
                Ok(())
            };

            search_futures.push(future);
        }

        // Execute all futures concurrently and collect results
        futures::future::try_join_all(search_futures).await?;

        Ok(())
    }
}

impl<
    const WORD_LENGTH: usize,
    Keyword: Send + Sync + Hash + Eq,
    Value: Send + Sync + Hash + Eq,
    EncodingError: Send + Sync + Debug + std::error::Error,
    BatcherMemory: Debug
        + Send
        + Sync
        + Clone
        + BatchingMemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> BatcherSSEADT<Keyword, Value>
    for BatcherFindex<WORD_LENGTH, Value, EncodingError, BatcherMemory>
{
    // type Findex = Findex<WORD_LENGTH, Value, EncodingError, BatcherMemory>;
    // type BatcherMemory = BatcherMemory;
    type Error = BatchFindexError<BatcherMemory>;

    async fn batch_search(
        &self,
        keywords: Vec<&Keyword>,
    ) -> Result<Vec<HashSet<Value>>, Self::Error> {
        let mut search_futures = Vec::new();
        let n = keywords.len();
        let buffered_memory = Arc::new(MemoryBatcher::new_reader(
            self.memory.clone(),
            AtomicUsize::new(n),
        ));

        for keyword in keywords {
            let buffered_memory_clone = buffered_memory.clone();
            let future = async move {
                // Create a temporary Findex instance using the shared batching layer
                let findex: Findex<
                    WORD_LENGTH,
                    Value,
                    EncodingError,
                    Arc<MemoryBatcher<BatcherMemory>>,
                > = Findex::<WORD_LENGTH, Value, EncodingError, _>::new(
                    buffered_memory_clone,
                    *self.encode,
                    *self.decode,
                );

                // Execute the search
                findex.search(keyword).await
            };

            search_futures.push(future);
        }
        // at this point nothing is polled yet

        // Execute all futures concurrently and collect results
        let results = futures::future::join_all(search_futures).await;

        // Process results
        let mut output = Vec::with_capacity(results.len());
        for result in results {
            output.push(result.unwrap());
        }

        Ok(output)
    }

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
}

// // The underlying tests assume the existence of a `Findex` implementation that is correct
// // The testing strategy for each function is to use the `Findex` implementation to perform the same operations
// // and compare the results with the `BatcherFindex` implementation.
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::{
//         ADDRESS_LENGTH, Error, Findex, InMemory, IndexADT, address::Address, dummy_decode,
//         dummy_encode,
//     };
//     use cosmian_crypto_core::define_byte_type;
//     use std::collections::HashSet;

//     type Value = Bytes<8>;
//     define_byte_type!(Bytes);

//     impl<const LENGTH: usize> TryFrom<usize> for Bytes<LENGTH> {
//         type Error = String;
//         fn try_from(value: usize) -> Result<Self, Self::Error> {
//             Self::try_from(value.to_be_bytes().as_slice()).map_err(|e| e.to_string())
//         }
//     }

//     const WORD_LENGTH: usize = 16;

//     #[tokio::test]
//     async fn test_batch_insert() {
//         let trivial_memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();

//         let batcher_findex = BatcherFindex::<WORD_LENGTH, Value, _, _>::new(
//             trivial_memory.clone(),
//             |op, values| {
//                 dummy_encode::<WORD_LENGTH, Value>(op, values)
//                     .map_err(|e| Error::<Address<ADDRESS_LENGTH>>::BatchedOperationError(e))
//             },
//             |words| {
//                 dummy_decode(words)
//                     .map_err(|e| Error::<Address<ADDRESS_LENGTH>>::BatchedOperationError(e))
//             },
//         );

//         let cat_bindings = vec![
//             Value::try_from(1).unwrap(),
//             Value::try_from(2).unwrap(),
//             Value::try_from(3).unwrap(),
//         ];
//         let dog_bindings = vec![
//             Value::try_from(4).unwrap(),
//             Value::try_from(5).unwrap(),
//             Value::try_from(6).unwrap(),
//         ];

//         // Batch insert multiple entries
//         let entries = vec![
//             ("cat".to_string(), cat_bindings.clone()),
//             ("dog".to_string(), dog_bindings.clone()),
//         ];

//         batcher_findex.batch_insert(entries).await.unwrap();

//         // instantiate a (non batched) Findex to verify the results
//         let findex = Findex::new(
//             trivial_memory.clone(),
//             dummy_encode::<WORD_LENGTH, Value>,
//             dummy_decode,
//         );

//         let cat_result = findex.search(&"cat".to_string()).await.unwrap();
//         assert_eq!(cat_result, cat_bindings.into_iter().collect::<HashSet<_>>());

//         let dog_result = findex.search(&"dog".to_string()).await.unwrap();
//         assert_eq!(dog_result, dog_bindings.into_iter().collect::<HashSet<_>>());
//     }

//     #[tokio::test]
//     async fn test_batch_delete() {
//         let trivial_memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();

//         // First, populate the memory with initial data using regular Findex
//         let findex = Findex::new(
//             trivial_memory.clone(),
//             dummy_encode::<WORD_LENGTH, Value>,
//             dummy_decode,
//         );

//         let cat_bindings = vec![
//             Value::try_from(1).unwrap(),
//             Value::try_from(3).unwrap(),
//             Value::try_from(5).unwrap(),
//             Value::try_from(7).unwrap(),
//         ];
//         let dog_bindings = vec![
//             Value::try_from(0).unwrap(),
//             Value::try_from(2).unwrap(),
//             Value::try_from(4).unwrap(),
//             Value::try_from(6).unwrap(),
//         ];

//         findex
//             .insert("cat".to_string(), cat_bindings.clone())
//             .await
//             .unwrap();
//         findex
//             .insert("dog".to_string(), dog_bindings.clone())
//             .await
//             .unwrap();

//         // Create BatcherFindex for deletion operations
//         let batcher_findex = BatcherFindex::<WORD_LENGTH, Value, _, _>::new(
//             trivial_memory.clone(),
//             |op, values| {
//                 dummy_encode::<WORD_LENGTH, Value>(op, values)
//                     .map_err(|e| Error::<Address<ADDRESS_LENGTH>>::BatchedOperationError(e))
//             },
//             |words| {
//                 dummy_decode(words)
//                     .map_err(|e| Error::<Address<ADDRESS_LENGTH>>::BatchedOperationError(e))
//             },
//         );

//         let delete_entries = vec![
//             (
//                 "cat".to_string(),
//                 vec![Value::try_from(1).unwrap(), Value::try_from(5).unwrap()],
//             ),
//             ("dog".to_string(), dog_bindings), // Remove all dog bindings
//         ];

//         // Perform batch delete
//         batcher_findex.batch_delete(delete_entries).await.unwrap();

//         // Verify deletions were performed using a regular findex instance
//         let cat_result = findex.search(&"cat".to_string()).await.unwrap();
//         let dog_result = findex.search(&"dog".to_string()).await.unwrap();

//         let expected_cat = vec![
//             Value::try_from(3).unwrap(), // 1 and 5 removed, 3 and 7 remain
//             Value::try_from(7).unwrap(),
//         ]
//         .into_iter()
//         .collect::<HashSet<_>>();
//         let expected_dog = HashSet::new(); // all of the dog bindings are removed

//         assert_eq!(cat_result, expected_cat);
//         assert_eq!(dog_result, expected_dog);
//     }

//     #[tokio::test]
//     async fn test_batch_search() {
//         let trivial_memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();

//         let findex = Findex::new(
//             trivial_memory.clone(),
//             dummy_encode::<WORD_LENGTH, Value>,
//             dummy_decode,
//         );
//         let cat_bindings = [
//             Value::try_from(1).unwrap(),
//             Value::try_from(3).unwrap(),
//             Value::try_from(5).unwrap(),
//         ];
//         let dog_bindings = [
//             Value::try_from(0).unwrap(),
//             Value::try_from(2).unwrap(),
//             Value::try_from(4).unwrap(),
//         ];
//         findex
//             .insert("cat".to_string(), cat_bindings.clone())
//             .await
//             .unwrap();
//         findex
//             .insert("dog".to_string(), dog_bindings.clone())
//             .await
//             .unwrap();

//         let batcher_findex = BatcherFindex::<WORD_LENGTH, Value, _, _>::new(
//             trivial_memory,
//             |op, values| {
//                 dummy_encode::<WORD_LENGTH, Value>(op, values)
//                     .map_err(|e| Error::<Address<ADDRESS_LENGTH>>::BatchedOperationError(e))
//             },
//             |words| {
//                 dummy_decode(words)
//                     .map_err(|e| Error::<Address<ADDRESS_LENGTH>>::BatchedOperationError(e))
//             },
//         );

//         let key1 = "cat".to_string();
//         let key2 = "dog".to_string();
//         // Perform batch search
//         let batch_search_results = batcher_findex
//             .batch_search(vec![&key1, &key2])
//             .await
//             .unwrap();

//         assert_eq!(
//             batch_search_results,
//             vec![
//                 cat_bindings.iter().cloned().collect::<HashSet<_>>(),
//                 dog_bindings.iter().cloned().collect::<HashSet<_>>()
//             ]
//         );
//     }
// }
