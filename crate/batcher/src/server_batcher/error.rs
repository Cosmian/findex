use super::buffer;
use std::fmt::{Debug, Display};

#[derive(Clone, Debug)]
pub enum Error<ServerError: std::error::Error> {
    Buffer(buffer::Error),
    Memory(ServerError),
    Batcher(String),
}

impl<ServerError: std::error::Error> Display for Error<ServerError> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Buffer(e) => write!(f, "buffer error: {e}"),
            Self::Memory(e) => write!(f, "memory error: {e}"),
            Self::Batcher(e) => write!(f, "server batcher error: {e}"),
        }
    }
}

impl<ServerError: std::error::Error> std::error::Error for Error<ServerError> {}

impl<ServerError: std::error::Error> From<buffer::Error> for Error<ServerError> {
    fn from(error: buffer::Error) -> Self {
        Self::Buffer(error)
    }
}
