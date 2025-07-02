// // entre la encryption layer et la storage layer
// // reçoit : "batch" de données de la encryption layer
// // envoie : UNE seule requete a la memory adt sous jacente

// use crate::{ADDRESS_LENGTH, Address, MemoryADT, WORD_LENGTH};

// pub trait BatchingLayerADT {
//     type Address;
//     type Word;
//     type Error;

//     /// Reads a batch of addresses and returns their corresponding words.
//     fn batch_read(
//         &self,
//         addresses: Vec<Self::Address>,
//     ) -> impl Send + std::prelude::rust_2024::Future<Output = Result<Vec<Option<Self::Word>>, Self::Error>>;

//     /// Writes a guarded write operation with bindings.
//     fn guarded_write(
//         &self,
//         guard: (Self::Address, Option<Self::Word>),
//         bindings: Vec<(Self::Address, Self::Word)>,
//     ) -> impl Send + std::prelude::rust_2024::Future<Output = Result<Option<Self::Word>, Self::Error>>;

//     /// Writes a batch of guarded write operations with bindings.
//     fn batch_guarded_write(
//         &self,
//         guard: (Self::Address, Option<Self::Word>),
//         bindings: Vec<(Self::Address, Self::Word)>,
//     ) -> impl Send + std::prelude::rust_2024::Future<Output = Result<Option<Self::Word>, Self::Error>>;
// }

// pub struct BatchingLayer<M: MemoryADT> {
//     memory_adt: M,
//     // INFO: autogen garbage

//     // pending_reads: HashMap<Address, Vec<ReadRequest>>,
//     // pending_writes: HashMap<Address, WriteOperation>,
//     // batch_size: usize,
//     // flush_timeout: Duration,
//     // last_flush: Instant,
// }

// impl<Memory: Send + Sync + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>>
//     BatchingLayerADT for BatchingLayer<Memory>
// {
//     type Address;
//     type Word;
//     type Error;

//     fn batch_read(
//         &self,
//         addresses: Vec<Self::Address>,
//     ) -> impl Send + std::prelude::rust_2024::Future<Output = Result<Vec<Option<Self::Word>>, Self::Error>>
//     {
//         todo!()
//     }

//     fn guarded_write(
//         &self,
//         guard: (Self::Address, Option<Self::Word>),
//         bindings: Vec<(Self::Address, Self::Word)>,
//     ) -> impl Send + std::prelude::rust_2024::Future<Output = Result<Option<Self::Word>, Self::Error>>
//     {
//         todo!()
//     }

//     fn batch_guarded_write(
//         &self,
//         guard: (Self::Address, Option<Self::Word>),
//         bindings: Vec<(Self::Address, Self::Word)>,
//     ) -> impl Send + std::prelude::rust_2024::Future<Output = Result<Option<Self::Word>, Self::Error>>
//     {
//         todo!()
//     }
// }
