use std::fmt::{Debug, Display};

pub enum Error {
    Internal(String),
    Server(String),
    Client(String),
}

impl Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Internal(e) => write!(f, "internal error: {e}"),
            Self::Server(e) => write!(f, "memory error: {e}"),
            Self::Client(e) => write!(f, "index error: {e}"),
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
