use std::hash::Hash;

use async_trait::async_trait;

mod primitives;
mod structs;
mod vera;

use crate::DbInterface;
pub use structs::{Dx, Edx, TagSet, Token, TokenSet};

#[async_trait(?Send)]
pub trait DynRhDxEnc<
    const VALUE_LENGTH: usize,
    Tag: Hash + Eq + PartialEq,
    DbConnection: DbInterface,
>: Sized
{
    type Error: std::error::Error;

    /// Creates a new instance of the scheme.
    ///
    /// Deterministically generates keys using the given seed and use the given
    /// database connection to store the EDX.
    fn setup(seed: &[u8], connection: DbConnection) -> Result<Self, Self::Error>;

    /// Returns the restriction of the stored DX to the given tags.
    async fn get(&self, tags: TagSet<Tag>) -> Result<Dx<Tag, VALUE_LENGTH>, Self::Error>;

    /// Merges the given DX to the stored one. Use the existing bindings in case
    /// of conflict.
    async fn insert(&self, dx: Dx<Tag, VALUE_LENGTH>)
        -> Result<Dx<Tag, VALUE_LENGTH>, Self::Error>;

    /// Removes any binding on the given tags from the stored DX.
    async fn delete(&self, tags: TagSet<Tag>) -> Result<(), Self::Error>;
}

#[async_trait(?Send)]
pub trait CsRhDxEnc<
    const VALUE_LENGTH: usize,
    Tag: Hash + Eq + PartialEq,
    DbConnection: DbInterface,
>: DynRhDxEnc<VALUE_LENGTH, Tag, DbConnection>
{
    /// Merges the given DX to the stored one. Use the existing bindings in case
    /// of conflict.
    ///
    /// Returns the restriction of the stored DX to the conflicting tags,
    /// alongside its EDX form.
    async fn insert(
        &self,
        dx: Dx<Tag, VALUE_LENGTH>,
    ) -> Result<(Dx<Tag, VALUE_LENGTH>, Edx), Self::Error>;

    /// Merges the given new DX to the stored one conditionally to the fact that
    /// for each tag, the ciphertext bound to this tag in the stored EDX is
    /// equal to the one bound to this tag in the given old EDX.
    ///
    /// Returns the restriction of the stored DX to the merge failures,
    /// alongside its raw EDX form.
    ///
    /// This operation ensures no concurrent modification of the stored DX can
    /// ever be overwritten.
    async fn upsert(
        &self,
        old_dx: Edx,
        new_dx: Dx<Tag, VALUE_LENGTH>,
    ) -> Result<(Dx<Tag, VALUE_LENGTH>, Edx), Self::Error>;

    /// Rebuilds the entire EDX using the given key.
    async fn rebuild(self, seed: &[u8]) -> Result<Self, Self::Error>;

    /// Returns the stored DX.
    async fn dump(&self) -> Result<Dx<Tag, VALUE_LENGTH>, Self::Error>;
}
