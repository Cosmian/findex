use std::hash::Hash;

mod primitives;
mod structs;
mod vera;

pub use structs::{Dx, Edx, Set, Tag, Token};
pub use vera::Vera;

pub trait DynRhDxEnc<const VALUE_LENGTH: usize>: Sized {
    /// The type of the connection to the DB used to store the EDX.
    type DbConnection;

    /// The type of error used by the scheme.
    type Error: std::error::Error;

    /// Type of the tags used by the scheme.
    ///
    /// Such tags need to be hashable.
    type Tag: Hash + PartialEq + Eq;

    /// The type of objects stored by the scheme.
    ///
    /// Such objects need to be convertible to a fixed length byte array to
    /// avoid leaking information.
    type Item: From<[u8; VALUE_LENGTH]> + Into<[u8; VALUE_LENGTH]>;

    /// Creates a new instance of the scheme.
    ///
    /// Deterministically generates keys using the given seed and use the given
    /// database connection to store the EDX.
    fn setup(seed: &[u8], connection: Self::DbConnection) -> Result<Self, Self::Error>;

    /// Returns the restriction of the stored DX to the given tags.
    async fn get(
        &self,
        tags: Set<Self::Tag>,
    ) -> Result<Dx<VALUE_LENGTH, Self::Tag, Self::Item>, Self::Error>;

    /// Merges the given DX to the stored one. Use the existing bindings in case
    /// of conflict.
    ///
    /// Returns the restriction of the stored DX to the conflicting tags.
    async fn insert(
        &self,
        dx: Dx<VALUE_LENGTH, Self::Tag, Self::Item>,
    ) -> Result<Dx<VALUE_LENGTH, Self::Tag, Self::Item>, Self::Error>;

    /// Removes any binding on the given tags from the stored DX.
    async fn delete(&self, tags: Set<Self::Tag>) -> Result<(), Self::Error>;

    /// Returns the entire dictionary stored.
    async fn dump(&self) -> Result<Dx<VALUE_LENGTH, Self::Tag, Self::Item>, Self::Error>;

    /// Gets the currently stored DX and stores it using the given connection
    /// under the given seed. Returns the new instance of the scheme allowing to
    /// manipulate this copy.
    async fn rebuild(
        &self,
        seed: &[u8],
        connection: Self::DbConnection,
    ) -> Result<Self, Self::Error>;
}

pub trait CsRhDxEnc<
    const TAG_LENGTH: usize,
    const VALUE_LENGTH: usize,
    Tag: Hash + PartialEq + Eq + From<[u8; TAG_LENGTH]> + Into<[u8; TAG_LENGTH]>,
>: DynRhDxEnc<VALUE_LENGTH, Tag = Tag>
{
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
        old_edx: Edx,
        new_dx: Dx<VALUE_LENGTH, Self::Tag, Self::Item>,
    ) -> Result<(Dx<VALUE_LENGTH, Self::Tag, Self::Item>, Edx), Self::Error>;
}
