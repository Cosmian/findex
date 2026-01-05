use std::ops::Add;

use cosmian_sse_memories::MemoryADT;

use crate::server_batcher::Error;

use super::MemoryBinding;

#[derive(Clone, Debug)]
pub(crate) enum MemoryOperation<M: MemoryADT> {
    BatchRead(Vec<M::Address>),
    GuardedWrite((M::Address, Option<M::Word>), Vec<MemoryBinding<M>>),
    BatchGuardedWrite(Vec<((M::Address, Option<M::Word>), Vec<MemoryBinding<M>>)>),
}

/*
 * Reducing a sequence of memory operations is an associative and commutative
 * operation, that can be represented by the sum of all individual operations.
 */

impl<M: MemoryADT> Add for MemoryOperation<M> {
    type Output = Result<Self, Error<M::Error>>;

    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::BatchRead(mut addresses_1), Self::BatchRead(mut addresses_2)) => {
                addresses_1.append(&mut addresses_2);
                Ok(Self::BatchRead(addresses_1))
            }
            (Self::GuardedWrite(guard1, bindings1), Self::GuardedWrite(guard2, bindings2)) => {
                Ok(Self::BatchGuardedWrite(vec![
                    (guard1, bindings1),
                    (guard2, bindings2),
                ]))
            }
            (
                Self::GuardedWrite(guard, bindings),
                Self::BatchGuardedWrite(mut guarded_bindings),
            )
            | (
                Self::BatchGuardedWrite(mut guarded_bindings),
                Self::GuardedWrite(guard, bindings),
            ) => {
                guarded_bindings.push((guard, bindings));
                Ok(Self::BatchGuardedWrite(guarded_bindings))
            }
            (Self::BatchGuardedWrite(mut bindings1), Self::BatchGuardedWrite(mut bindings2)) => {
                bindings1.append(&mut bindings2);
                Ok(Self::BatchGuardedWrite(bindings1))
            }
            (Self::BatchRead(_), Self::GuardedWrite(_, _))
            | (Self::BatchRead(_), Self::BatchGuardedWrite(_))
            | (Self::GuardedWrite(_, _), Self::BatchRead(_))
            | (Self::BatchGuardedWrite(_), Self::BatchRead(_)) => Err(Error::Batcher(
                "cannot reduce heterogeneous operations".to_string(),
            )),
        }
    }
}

pub(crate) enum MemoryResult<M: MemoryADT> {
    BatchRead(Vec<Option<M::Word>>),
    GuardedWrite(Option<M::Word>),
}
