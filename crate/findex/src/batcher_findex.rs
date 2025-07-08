use crate::adt::{BatcherSSEADT, BatchingMemoryADT};
use crate::memory::MemoryBatcher;
use crate::{ADDRESS_LENGTH, Address, Decoder, Encoder, Error, Findex, IndexADT};
use std::fmt::Display;
use std::sync::atomic::AtomicUsize;
use std::{collections::HashSet, fmt::Debug, hash::Hash, sync::Arc};
// TODO : should all of these be sync ?

// ---------------------------- BatcherFindex Structure -----------------------------
// He is a bigger findex that does findex operations but in batches lol

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
// batching_layer: Arc<BatcherMemory>,
// findex: Findex<WORD_LENGTH, Value, EncodingError, Arc<BatcherMemory>>,
impl<
    const WORD_LENGTH: usize,
    Value: Send + Sync + Hash + Eq,
    BatcherMemory: Send
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
    ) -> Result<(), Error<Address<ADDRESS_LENGTH>>>
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

                if is_insert {
                    findex.insert(guard_keyword, bindings).await.unwrap(); // TODO: add to errors
                } else {
                    findex.delete(guard_keyword, bindings).await.unwrap(); // TODO: add to errors
                }
                // once one of the operations succeeds, we should make the buffer smaller
                memory_arc.decrement_capacity();
            };

            search_futures.push(future);
        }

        // Execute all futures concurrently and collect results
        futures::future::join_all(search_futures).await;

        Ok(())
    }
}

impl<
    const WORD_LENGTH: usize,
    Keyword: Send + Sync + Hash + Eq,
    Value: Send + Sync + Hash + Eq,
    EncodingError: Send + Sync + Debug + std::error::Error,
    BatcherMemory: Send
        + Sync
        + Clone
        + BatchingMemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> BatcherSSEADT<Keyword, Value>
    for BatcherFindex<WORD_LENGTH, Value, EncodingError, BatcherMemory>
{
    // type Findex = Findex<WORD_LENGTH, Value, EncodingError, BatcherMemory>;
    // type BatcherMemory = BatcherMemory;
    type Error = Error<Address<ADDRESS_LENGTH>>;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ADDRESS_LENGTH, Error, Findex, InMemory, IndexADT, address::Address, dummy_decode,
        dummy_encode,
    };
    use cosmian_crypto_core::define_byte_type;
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_batch_insert() {
        type Value = Bytes<8>;
        define_byte_type!(Bytes);

        impl<const LENGTH: usize> TryFrom<usize> for Bytes<LENGTH> {
            type Error = String;
            fn try_from(value: usize) -> Result<Self, Self::Error> {
                Self::try_from(value.to_be_bytes().as_slice()).map_err(|e| e.to_string())
            }
        }

        const WORD_LENGTH: usize = 16;

        let garbage_memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();

        let batcher_findex = BatcherFindex::<WORD_LENGTH, Value, _, _>::new(
            garbage_memory.clone(),
            |op, values| {
                dummy_encode::<WORD_LENGTH, Value>(op, values)
                    .map_err(|e| Error::<Address<ADDRESS_LENGTH>>::DefaultGenericErrorForBatcher(e))
            },
            |words| {
                dummy_decode(words)
                    .map_err(|e| Error::<Address<ADDRESS_LENGTH>>::DefaultGenericErrorForBatcher(e))
            },
        );

        // Prepare test data
        let cat_bindings = vec![
            Value::try_from(1).unwrap(),
            Value::try_from(3).unwrap(),
            Value::try_from(5).unwrap(),
        ];
        let dog_bindings = vec![
            Value::try_from(0).unwrap(),
            Value::try_from(2).unwrap(),
            Value::try_from(4).unwrap(),
        ];
        let fish_bindings = vec![Value::try_from(7).unwrap(), Value::try_from(9).unwrap()];

        // Batch insert multiple entries
        let entries = vec![
            ("cat".to_string(), cat_bindings.clone()),
            ("dog".to_string(), dog_bindings.clone()),
            ("fish".to_string(), fish_bindings.clone()),
        ];

        batcher_findex.batch_insert(entries).await.unwrap();

        // Verify insertions by searching
        let key1 = "cat".to_string();
        let key2 = "dog".to_string();
        let key3 = "fish".to_string();
        let findex = Findex::new(
            garbage_memory.clone(),
            dummy_encode::<WORD_LENGTH, Value>,
            dummy_decode,
        );

        let cat_result = findex.search(&"cat".to_string()).await.unwrap();
        let dog_result = findex.search(&"dog".to_string()).await.unwrap();
        let fish_result = findex.search(&"fish".to_string()).await.unwrap();

        // assert_eq!(cat_result, cat_bindings.into_iter().collect::<HashSet<_>>());
        // assert_eq!(dog_result, dog_bindings.into_iter().collect::<HashSet<_>>());
        // assert_eq!(
        //     fish_result,
        //     fish_bindings.into_iter().collect::<HashSet<_>>()
        // );

        println!("Cat result: {:?}", cat_result);
        println!("Dog result: {:?}", dog_result);
        println!("Fish result: {:?}", fish_result);
        // assert_eq!(results[0], cat_bindings.into_iter().collect::<HashSet<_>>());
        // assert_eq!(results[1], dog_bindings.into_iter().collect::<HashSet<_>>());
        // assert_eq!(
        //     results[2],
        //     fish_bindings.into_iter().collect::<HashSet<_>>()
        // );
    }

    #[tokio::test]
    // TODO!: I didn't write this one test it's autogen - to not delete this comment before rewriting it !!!
    async fn test_batch_delete() {
        type Value = Bytes<8>;
        define_byte_type!(Bytes);

        impl<const LENGTH: usize> TryFrom<usize> for Bytes<LENGTH> {
            type Error = String;
            fn try_from(value: usize) -> Result<Self, Self::Error> {
                Self::try_from(value.to_be_bytes().as_slice()).map_err(|e| e.to_string())
            }
        }

        const WORD_LENGTH: usize = 16;

        let garbage_memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();

        // First, populate the memory with initial data using regular Findex
        let findex = Findex::new(
            garbage_memory.clone(),
            dummy_encode::<WORD_LENGTH, Value>,
            dummy_decode,
        );

        // Prepare initial test data
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
        let fish_bindings = vec![
            Value::try_from(8).unwrap(),
            Value::try_from(9).unwrap(),
            Value::try_from(10).unwrap(),
        ];

        // Insert initial data
        findex
            .insert("cat".to_string(), cat_bindings.clone())
            .await
            .unwrap();
        findex
            .insert("dog".to_string(), dog_bindings.clone())
            .await
            .unwrap();
        findex
            .insert("fish".to_string(), fish_bindings.clone())
            .await
            .unwrap();

        // Create BatcherFindex for deletion operations
        let batcher_findex = BatcherFindex::<WORD_LENGTH, Value, _, _>::new(
            garbage_memory.clone(),
            |op, values| {
                dummy_encode::<WORD_LENGTH, Value>(op, values)
                    .map_err(|e| Error::<Address<ADDRESS_LENGTH>>::DefaultGenericErrorForBatcher(e))
            },
            |words| {
                dummy_decode(words)
                    .map_err(|e| Error::<Address<ADDRESS_LENGTH>>::DefaultGenericErrorForBatcher(e))
            },
        );

        // Verify initial state
        let initial_cat = findex.search(&"cat".to_string()).await.unwrap();
        let initial_dog = findex.search(&"dog".to_string()).await.unwrap();
        let initial_fish = findex.search(&"fish".to_string()).await.unwrap();

        println!("Initial cat result: {:?}", initial_cat);
        println!("Initial dog result: {:?}", initial_dog);
        println!("Initial fish result: {:?}", initial_fish);

        // Prepare deletion entries - delete some values from each keyword
        let delete_entries = vec![
            (
                "cat".to_string(),
                vec![
                    Value::try_from(1).unwrap(), // Remove 1
                    Value::try_from(5).unwrap(), // Remove 5
                ],
            ),
            (
                "dog".to_string(),
                vec![
                    Value::try_from(0).unwrap(), // Remove 0
                    Value::try_from(4).unwrap(), // Remove 4
                ],
            ),
            (
                "fish".to_string(),
                vec![
                    Value::try_from(9).unwrap(), // Remove 9
                ],
            ),
        ];

        // Perform batch delete
        batcher_findex.batch_delete(delete_entries).await.unwrap();

        // Verify deletions by searching with fresh Findex instance
        let verification_findex = Findex::new(
            garbage_memory.clone(),
            dummy_encode::<WORD_LENGTH, Value>,
            dummy_decode,
        );

        let cat_after_delete = verification_findex
            .search(&"cat".to_string())
            .await
            .unwrap();
        let dog_after_delete = verification_findex
            .search(&"dog".to_string())
            .await
            .unwrap();
        let fish_after_delete = verification_findex
            .search(&"fish".to_string())
            .await
            .unwrap();

        println!("Cat after delete: {:?}", cat_after_delete);
        println!("Dog after delete: {:?}", dog_after_delete);
        println!("Fish after delete: {:?}", fish_after_delete);

        // Expected results after deletion
        let expected_cat = vec![
            Value::try_from(3).unwrap(), // 1 and 5 removed, 3 and 7 remain
            Value::try_from(7).unwrap(),
        ]
        .into_iter()
        .collect::<HashSet<_>>();

        let expected_dog = vec![
            Value::try_from(2).unwrap(), // 0 and 4 removed, 2 and 6 remain
            Value::try_from(6).unwrap(),
        ]
        .into_iter()
        .collect::<HashSet<_>>();

        let expected_fish = vec![
            Value::try_from(8).unwrap(), // 9 removed, 8 and 10 remain
            Value::try_from(10).unwrap(),
        ]
        .into_iter()
        .collect::<HashSet<_>>();

        // Verify the deletions worked correctly
        assert_eq!(cat_after_delete, expected_cat);
        assert_eq!(dog_after_delete, expected_dog);
        assert_eq!(fish_after_delete, expected_fish);
    }

    #[tokio::test]
    async fn test_search_lol() {
        // Define a byte type, and use `Value` as an alias for 8-bytes values of
        // that type.
        type Value = Bytes<8>;

        define_byte_type!(Bytes);

        impl<const LENGTH: usize> TryFrom<usize> for Bytes<LENGTH> {
            type Error = String;
            fn try_from(value: usize) -> Result<Self, Self::Error> {
                Self::try_from(value.to_be_bytes().as_slice()).map_err(|e| e.to_string())
            }
        }

        const WORD_LENGTH: usize = 16;

        let garbage_memory = InMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::default();

        let findex = Findex::new(
            garbage_memory.clone(),
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
        let cat_res = findex.search(&"cat".to_string()).await.unwrap();
        let dog_res = findex.search(&"dog".to_string()).await.unwrap();
        assert_eq!(
            cat_bindings.iter().cloned().collect::<HashSet<_>>(),
            cat_res
        );
        assert_eq!(
            dog_bindings.iter().cloned().collect::<HashSet<_>>(),
            dog_res
        );

        // all of the previous garbage is the classic findex tests, now we will try to retrieve the same values using butcher findex
        let key1 = "cat".to_string();
        let key2 = "dog".to_string();
        let cat_dog_input = vec![&key1, &key2];

        let batcher_findex = BatcherFindex::<WORD_LENGTH, Value, _, _>::new(
            garbage_memory,
            |op, values| {
                dummy_encode::<WORD_LENGTH, Value>(op, values)
                    .map_err(|e| Error::<Address<ADDRESS_LENGTH>>::DefaultGenericErrorForBatcher(e))
            },
            |words| {
                dummy_decode(words)
                    .map_err(|e| Error::<Address<ADDRESS_LENGTH>>::DefaultGenericErrorForBatcher(e))
            },
        );

        let res = batcher_findex.batch_search(cat_dog_input).await.unwrap();
        println!("cat bindings: {cat_res:?}\n");
        println!("dog bindings: {dog_res:?}\n");
        println!("results of a batch_search performed on the vector Vec![cat, dog]: \n {res:?}\n");
    }
}
