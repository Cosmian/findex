use std::fmt;

#[derive(Debug)]
pub enum PostgresMemoryError {
    TokioPostgresError(tokio_postgres::Error),
    TryFromSliceError(std::array::TryFromSliceError),
    BuildPoolError(deadpool_postgres::BuildError),
    GetConnectionFromPoolError(deadpool_postgres::PoolError),
    CreatePoolError(deadpool_postgres::CreatePoolError),
    RetryExhaustedError(usize),
    InvalidDataLength(usize),
}

impl std::error::Error for PostgresMemoryError {}

impl fmt::Display for PostgresMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokioPostgresError(err) => write!(f, "tokio-postgres error: {}", err),
            Self::TryFromSliceError(err) => write!(f, "try_from_slice error: {}", err),
            Self::InvalidDataLength(len) => {
                write!(
                    f,
                    "invalid data length: received {} bytes from db instead of WORD_LENGTH bytes",
                    len
                )
            }
            Self::CreatePoolError(err) => {
                write!(f, "deadpool_postgres error during pool creation: {}", err)
            }
            Self::BuildPoolError(err) => {
                write!(f, "deadpool_postgres error during pool build: {}", err)
            }
            Self::GetConnectionFromPoolError(err) => write!(
                f,
                "deadpool_postgres error while trying to get a connection from the pool: {}",
                err
            ),
            Self::RetryExhaustedError(retries) => {
                write!(f, "retries exhausted after {} attempts", retries)
            }
        }
    }
}

impl From<tokio_postgres::Error> for PostgresMemoryError {
    fn from(err: tokio_postgres::Error) -> Self {
        Self::TokioPostgresError(err)
    }
}

impl From<std::array::TryFromSliceError> for PostgresMemoryError {
    fn from(err: std::array::TryFromSliceError) -> Self {
        Self::TryFromSliceError(err)
    }
}

impl From<deadpool_postgres::CreatePoolError> for PostgresMemoryError {
    fn from(err: deadpool_postgres::CreatePoolError) -> Self {
        Self::CreatePoolError(err)
    }
}

impl From<deadpool_postgres::BuildError> for PostgresMemoryError {
    fn from(err: deadpool_postgres::BuildError) -> Self {
        Self::BuildPoolError(err)
    }
}

impl From<deadpool_postgres::PoolError> for PostgresMemoryError {
    fn from(err: deadpool_postgres::PoolError) -> Self {
        Self::GetConnectionFromPoolError(err)
    }
}
