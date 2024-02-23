use std::fmt::Display;

use crate::CoreError;

mod findex;
mod structs;

pub use findex::Findex;
pub use structs::{Link, Metadata};

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
