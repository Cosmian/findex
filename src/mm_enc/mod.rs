use std::{fmt::Display, hash::Hash};

use crate::{dx_enc::Set, CoreError};

mod findex;
mod structs;

pub use findex::Findex;
pub use structs::{Mm, METADATA_LENGTH};

pub trait CsRhMmEnc: Sized {
    /// Type of the tags used by the scheme.
    type Tag: Hash + PartialEq + Eq;

    /// The type of objects stored by the scheme.
    type Item;

    /// The type of the connection to the DB used to store the EMM.
    type DbConnection;

    /// The type of error used by the scheme.
    type Error: std::error::Error;

    /// Creates a new instance of the scheme.
    ///
    /// Deterministically generates keys using the given seed and use the given
    /// database connection to store the EMM.
    fn setup(seed: &[u8], connection: Self::DbConnection) -> Result<Self, Self::Error>;

    /// Returns a restriction of the stored MM to the given tags.
    async fn search(&self, tags: Set<Self::Tag>) -> Result<Mm<Self::Tag, Self::Item>, Self::Error>;

    /// Extends the stored MM with the given one.
    async fn insert(&self, mm: Mm<Self::Tag, Self::Item>) -> Result<(), Self::Error>;

    /// Extracts the given MM out of the stored one.
    async fn delete(&self, mm: Mm<Self::Tag, Self::Item>) -> Result<(), Self::Error>;

    /// Rebuilds the stored EMM using the given seed.
    async fn rebuild(
        &self,
        seed: &[u8],
        connection: Self::DbConnection,
    ) -> Result<Self, Self::Error>;
}

#[derive(Debug)]
pub enum Error<EntryError: std::error::Error, ChainError: std::error::Error> {
    Core(CoreError),
    Entry(EntryError),
    Chain(ChainError),
}

impl<EntryError: std::error::Error, ChainError: std::error::Error> From<CoreError>
    for Error<EntryError, ChainError>
{
    fn from(e: CoreError) -> Self {
        Self::Core(e)
    }
}

impl<EntryError: std::error::Error, ChainError: std::error::Error> Display
    for Error<EntryError, ChainError>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Entry(e) => write!(f, "Entry DX-Enc error: {e}"),
            Error::Chain(e) => write!(f, "Chain DX-Enc error: {e}"),
            Error::Core(e) => write!(f, "{e}"),
        }
    }
}

impl<EntryError: std::error::Error, ChainError: std::error::Error> std::error::Error
    for Error<EntryError, ChainError>
{
}
