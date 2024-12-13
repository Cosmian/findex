use std::fmt::{Debug, Display};

#[derive(Debug)]
pub enum Error<Address: Debug, MemoryError: std::error::Error> {
    Parsing(String),
    Memory(MemoryError),
    Conversion(String),
    MissingValue(Address, usize),
    CorruptedMemoryCache,
}

impl<Address: Debug, MemoryError: std::error::Error> Display for Error<Address, MemoryError> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl<Address: Debug, MemoryError: std::error::Error> std::error::Error
    for Error<Address, MemoryError>
{
}

impl<Address: Debug, MemoryError: std::error::Error> From<MemoryError>
    for Error<Address, MemoryError>
{
    fn from(e: MemoryError) -> Self {
        Self::Memory(e)
    }
}
