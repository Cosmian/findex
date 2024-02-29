mod implem;
mod primitives;
mod structs;

use std::fmt::Display;

pub use implem::Vera;
pub use structs::Tag;

use crate::CoreError;

#[derive(Debug)]
pub enum Error<DbConnectionError: std::error::Error> {
    Core(CoreError),
    Db(DbConnectionError),
}

impl<DbConnectionError: std::error::Error> Display for Error<DbConnectionError> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Core(e) => write!(f, "Core error: {e}"),
            Error::Db(e) => write!(f, "Db connection error: {e}"),
        }
    }
}

impl<DbConnectionError: std::error::Error> std::error::Error for Error<DbConnectionError> {}
