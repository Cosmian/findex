use std::fmt::{Debug, Display};

#[derive(Debug)]
pub enum Error<Address> {
    Parsing(String),
    Memory(String),
    Conversion(String),
    MissingValue(Address, usize),
    CorruptedMemoryCache,
    DefaultGenericErrorForBatcher(String), // TODO: redirect batcher errors to this for now
}

impl<Address: Debug> Display for Error<Address> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<Address: Debug> std::error::Error for Error<Address> {}
