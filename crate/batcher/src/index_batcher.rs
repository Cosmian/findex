use crate::{ClientServerADT, ServerBatcher, error::Error};
use cosmian_findex::IndexADT;
use std::{collections::HashSet, fmt::Debug, hash::Hash, marker::PhantomData};

#[derive(Debug, Clone)]
pub struct IndexBatcher<Keyword, Value, Index>
where
    Keyword: Send + Hash,
    Value: Send + Hash,
    Index: IndexADT<Keyword, Value> + ClientServerADT,
    Index::ServerInterface: ServerBatcher,
{
    kv: PhantomData<(Keyword, Value, Index)>,
    srv: Index::ServerInterface,
    params: Index::ClientParameters,
}

impl<Keyword, Value, Index> IndexBatcher<Keyword, Value, Index>
where
    Keyword: Send + Sync + Hash,
    Value: Send + Sync + Hash,
    Index: Send + Sync + IndexADT<Keyword, Value> + ClientServerADT,
    Index::ServerInterface: Send + Sync + Clone + ServerBatcher,
    Index::ClientParameters: Send + Sync + Clone,
{
    pub fn new(
        srv: <Index::ServerInterface as ServerBatcher>::Srv,
        params: Index::ClientParameters,
    ) -> Self {
        Self {
            kv: PhantomData,
            srv: <Index::ServerInterface as ServerBatcher>::new(srv),
            params,
        }
    }

    async fn batch_insert(&self, args: Vec<(Keyword, HashSet<Value>)>) -> Result<(), Error> {
        assert_eq!(0, self.srv.buffer_length());

        self.srv
            .resize(args.len())
            .map_err(|e| Error::Internal(e.to_string()))?;

        let mut futures = Vec::with_capacity(args.len());
        for (keyword, values) in args {
            let srv = self.srv.clone();
            futures.push(async move {
                let idx = Index::connect(srv.clone(), self.params.clone())
                    .map_err(|e| Error::Client(e.to_string()))?;
                idx.insert(keyword, values)
                    .await
                    .map_err(|e| Error::Client(e.to_string()))?;
                srv.shrink().map_err(|e| Error::Server(e.to_string()))?;
                Ok::<_, Error>(())
            });
        }

        assert_eq!(0, self.srv.buffer_length());
        todo!()
    }
}

// impl<
//     const WORD_LENGTH: usize,
//     Value: Send + Hash + Eq,
//     BatcherMemory: Debug
//         + Send
//         + Sync
//         + Clone
//         + BatchingMemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
//     EncodingError: Send + Debug,
// > IndexBatcher<WORD_LENGTH, Value, EncodingError, BatcherMemory>
// {
//     pub fn new(
//         memory: BatcherMemory,
//         encode: Encoder<Value, BatcherMemory::Word, EncodingError>,
//         decode: Decoder<Value, BatcherMemory::Word, EncodingError>,
//     ) -> Self {
//         Self {
//             memory,
//             encode,
//             decode,
//         }
//     }

//     async fn batch_insert_or_delete<Keyword, Bindings, Entries>(
//         &self,
//         entries: Entries,
//         is_insert: bool,
//     ) -> Result<(), Error>
//     where
//         Keyword: Send + Sync + Hash + Eq,
//         Bindings: Send + IntoIterator<Item = Value>,
//         Entries: IntoIterator<Item = (Keyword, Bindings)> + Send,
//         Entries::IntoIter: ExactSizeIterator,
//     {
//         let entries = entries.into_iter();
//         let n = entries.len();
//         let mut futures = Vec::with_capacity(n);
//         let memory = MemoryBatcher::new(
//             self.memory.clone(),
//             NonZero::new(n)
//                 .ok_or_else(|| Error::Internal("Batch size can not be zero".to_owned()))?,
//         );

//         for (guard_keyword, bindings) in entries {
//             let memory = memory.clone();
//             // Create a temporary Findex instance using the shared batching layer.
//             let findex = Findex::<WORD_LENGTH, Value, EncodingError, _>::new(
//                 memory.clone(),
//                 self.encode,
//                 self.decode,
//             );

//             let future = async move {
//                 if is_insert {
//                     findex.insert(guard_keyword, bindings).await
//                 } else {
//                     findex.delete(guard_keyword, bindings).await
//                 }?;
//                 // Within findex, insert/delete operations may perform a variable number of
//                 // memory writes. This requires explicit `unsubscribe()` calls
//                 // to adjust the expected buffer size once one of the operations succeeds.
//                 memory
//                     .unsubscribe()
//                     .await
//                     .map_err(|e| Error::Memory(e.to_string()))?;

//                 Ok::<_, Error>(())
//             };

//             futures.push(future);
//         }

//         // Execute all futures concurrently and collect results.
//         futures::future::try_join_all(futures).await?;

//         Ok(())
//     }

//     async fn batch_insert<Bindings, Entries>(&self, entries: Entries) -> Result<(), Self::Error>
//     where
//         Bindings: Send + IntoIterator<Item = Value>,
//         Entries: Send + IntoIterator<Item = (Keyword, Bindings)>,
//         Entries::IntoIter: ExactSizeIterator,
//     {
//         self.batch_insert_or_delete(entries, true).await
//     }

//     async fn batch_delete<Bindings, Entries>(&self, entries: Entries) -> Result<(), Self::Error>
//     where
//         Bindings: Send + IntoIterator<Item = Value>,
//         Entries: Send + IntoIterator<Item = (Keyword, Bindings)>,
//         Entries::IntoIter: ExactSizeIterator,
//     {
//         self.batch_insert_or_delete(entries, false).await
//     }

//     async fn batch_search(
//         &self,
//         keywords: Vec<&Keyword>,
//     ) -> Result<Vec<HashSet<Value>>, Self::Error> {
//         let n = keywords.len();
//         let mut futures = Vec::with_capacity(n);
//         let memory = MemoryBatcher::new(
//             self.memory.clone(),
//             NonZero::new(n)
//                 .ok_or_else(|| BatchFindexError::Other("Batch size can not be zero".to_owned()))?,
//         );

//         for keyword in keywords {
//             let memory = memory.clone();
//             let findex = Findex::<WORD_LENGTH, Value, EncodingError, _>::new(
//                 memory,
//                 self.encode,
//                 self.decode,
//             );
//             // Search operations do not require calling `unsubscribe()` on the memory
//             // batcher. This is because all Findex search operations perform the
//             // same deterministic number of memory read operations.
//             // Specifically, each (safe) Findex search completes after
//             // performing exactly two reads.
//             let future = async move { findex.search(keyword).await };
//             futures.push(future);
//         }

//         futures::future::try_join_all(futures)
//             .await
//             .map_err(|e| Error::Index(e.to_string()))
//     }
// }
