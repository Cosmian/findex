use std::fmt::Display;

use cosmian_crypto_core::CryptoCoreError;

#[derive(Debug)]
pub struct Error(pub String);

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.0)
    }
}

impl std::error::Error for Error {}

impl From<CryptoCoreError> for Error {
    fn from(error: CryptoCoreError) -> Self {
        Self(error.to_string())
    }
}

mod bindings {
    use super::*;
    use cosmian_sse_memories::PostgresMemoryError;

    impl From<PostgresMemoryError> for Error {
        fn from(error: PostgresMemoryError) -> Self {
            Self(error.to_string())
        }
    }
}
