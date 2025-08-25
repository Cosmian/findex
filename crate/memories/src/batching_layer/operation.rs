// I am bothered by the predominance of all those `oneshot` dependencies.
// Arguably, this choice of dependency should be the responsibility of the
// implementation. At the very least, try to factorize it using a type
// declaration to make it *look* more independent.

//! This module strongly types and defines the variables that are used within
//! the batching layer. It adds clear distinction between :
//! - An `input` (resp. `output`) type, which the memory backend accepts (resp.
//!   returns) via its `MemoryADT` implementation.
//! - An operation type, which is a pair of an input and a oneshot channel. An
//!   operation is considered *pending* starting from the moment it is pushed to
//!   the buffer,
// The end of this paragraph does not make any sense.
//!   and to each operation corresponds exactly one result consisting of
//!   an output that  can be retrieved from the oneshot channel (or otherwise an
//!   error).

use futures::channel::oneshot;

use crate::{BatchingMemoryADT, MemoryADT};

pub(crate) type BatchReadInput<M> = Vec<<M as MemoryADT>::Address>;
pub(crate) type GuardedWriteInput<M> = (
    (<M as MemoryADT>::Address, Option<<M as MemoryADT>::Word>),
    Vec<(<M as MemoryADT>::Address, <M as MemoryADT>::Word)>,
);

// TBZ: I am not sure since its only purpose it to server here. This needs to be
// thought through. Remove the comment for now.
// Notice: to avoid breaking changes, the MemoryADT I/O types are kept here for
// now. If a major release is planned, consider moving them to the MemoryADT
// module.
pub(crate) enum MemoryInput<M: MemoryADT> {
    Read(BatchReadInput<M>),
    Write(GuardedWriteInput<M>),
}

pub(crate) type BatchReadOutput<M> = Vec<Option<<M as MemoryADT>::Word>>;
pub(crate) type GuardedWriteOutput<M> = Option<<M as MemoryADT>::Word>;

#[derive(Debug)]
pub enum MemoryOutput<M: MemoryADT>
where
    M::Word: std::fmt::Debug,
{
    Read(BatchReadOutput<M>),
    Write(GuardedWriteOutput<M>),
}

pub(crate) type ReadOperation<M> = (
    BatchReadInput<M>,
    oneshot::Sender<Result<BatchReadOutput<M>, <M as MemoryADT>::Error>>,
);

pub(crate) type WriteOperation<M> = (
    GuardedWriteInput<M>,
    oneshot::Sender<Result<GuardedWriteOutput<M>, <M as MemoryADT>::Error>>,
);

pub(crate) enum Operation<M: BatchingMemoryADT> {
    Read(ReadOperation<M>),
    Write(WriteOperation<M>),
}

pub(crate) type PendingOperations<M> = Vec<Operation<M>>;

// Match arms do not support heterogeneous types, this enum is the only way to
// escape a 2 branch `apply` function and the code duplication that would imply.
pub(crate) enum OperationResultReceiver<M: MemoryADT> {
    Read(oneshot::Receiver<Result<BatchReadOutput<M>, <M as MemoryADT>::Error>>),
    Write(oneshot::Receiver<Result<GuardedWriteOutput<M>, <M as MemoryADT>::Error>>),
}
