pub(crate) mod operation;
mod batcher;

#[cfg(feature = "postgres")]
mod postresql;

pub use batcher::MemoryBatcher;

use cosmian_sse_memories::MemoryADT;
use std::future::Future;

pub type MemoryBinding<M> = (<M as MemoryADT>::Address, <M as MemoryADT>::Word);

pub trait BatchingMemoryADT: Sized + MemoryADT {
    /*
     * This trait is required in order to batch guarded writes since they cannot
     * be reduced to a single guarded write.
     */
    fn batch_guarded_write(
        &self,
        write_operations: Vec<(
            (Self::Address, Option<Self::Word>),
            Vec<MemoryBinding<Self>>,
        )>,
    ) -> impl Send + Future<Output = Result<Vec<Option<Self::Word>>, Self::Error>>;
}
