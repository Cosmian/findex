use crate::{Address, MemoryADT};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params_from_iter, types::ToSqlOutput};
use std::{
    collections::HashMap,
    marker::PhantomData,
    num::NonZero,
    path::Path,
    thread::{available_parallelism, sleep},
    time::Duration,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SqlMemoryError {
    #[error("Sql store memory error: {0}")]
    SqlError(#[from] rusqlite::Error),
    #[error("r2d2 pooling error: {0}")]
    PoolingError(#[from] r2d2::Error),
}

#[derive(Debug, Clone)]
pub struct SqlMemory<Address, Word> {
    pool: Pool<SqliteConnectionManager>,
    // only enable this in case of a high contention scenario
    exponential_backoff: bool,
    _marker: PhantomData<(Address, Word)>,
}

const CREATE_TABLE_SCRIPT: &str = "
CREATE TABLE IF NOT EXISTS memory
(
    a BLOB PRIMARY KEY,
    w BLOB NOT NULL
)";

impl<Address, Word> SqlMemory<Address, Word> {
    /// Get the number of CPUs available on the system.
    fn get_cpu_count() -> u32 {
        // Using less connections than the number of CPUs underuses the available ressources
        // while using more connections than the number of CPUs can increase contention.
        available_parallelism()
            .unwrap_or(NonZero::new(1).unwrap())
            .get() as u32 // safe cast
    }

    /// Create a new in-memory database.
    pub fn in_memory(backoff: Option<bool>) -> Result<Self, SqlMemoryError> {
        let pool = r2d2::Pool::builder()
            .max_size(Self::get_cpu_count())
            .build(SqliteConnectionManager::memory())?;
        pool.get().unwrap().execute(CREATE_TABLE_SCRIPT, [])?;
        Ok(Self {
            pool,
            exponential_backoff: backoff.unwrap_or(false),
            _marker: PhantomData,
        })
    }

    /// Connects to a known DB using the given path.
    pub fn connect(path: &impl AsRef<Path>, backoff: Option<bool>) -> Result<Self, SqlMemoryError> {
        // SqliteConnectionManager::file is the equivalent of using
        // `rusqlite::Connection::open` as documented in the function's source
        // code.
        let pool = r2d2::Pool::builder()
            .max_size(Self::get_cpu_count())
            .build(SqliteConnectionManager::file(path))?;
        pool.get().unwrap().execute(CREATE_TABLE_SCRIPT, [])?;

        Ok(Self {
            pool,
            exponential_backoff: backoff.unwrap_or(false),
            _marker: PhantomData,
        })
    }
}

impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize> MemoryADT
    for SqlMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    type Address = Address<ADDRESS_LENGTH>;
    type Error = SqlMemoryError;
    type Word = [u8; WORD_LENGTH];

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.pool.get()?;

        let query = format!(
            "SELECT a, w FROM memory WHERE a IN ({})",
            (0..addresses.len())
                .map(|_| "?")
                .collect::<Vec<&str>>()
                .join(",")
        );

        let params: Vec<ToSqlOutput> = addresses
            .iter()
            .map(|addr| {
                rusqlite::types::ToSqlOutput::Borrowed(rusqlite::types::ValueRef::Blob(&**addr))
            })
            .collect();

        let result_map = conn
            .prepare(&query)?
            .query_map(rusqlite::params_from_iter(params), |row| {
                let adr: Self::Address = row.get::<_, [u8; ADDRESS_LENGTH]>(0)?.into();
                let word: Self::Word = row.get(1)?;
                Ok((adr, word))
            })?
            .collect::<Result<HashMap<Self::Address, Self::Word>, _>>()?;

        let results = addresses
            .iter()
            .map(|addr| result_map.get(addr).copied())
            .collect();

        Ok(results)
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let mut conn = self.pool.get()?;

        let (ga, gw) = guard;

        let tx = conn.transaction()?;
        // Sets an implicit `busy_handler` that sleeps for a specified amount of time when a
        // table is locked, handling `SQLITE_BUSY` errors. The handler will sleep multiple
        // times until at least 5000 milliseconds of sleeping have accumulated.
        // The value of `5000ms` is the current default busy timeout for new connections.
        tx.busy_timeout(Duration::from_millis(5000))?;

        let select_query = "SELECT w FROM memory WHERE a = ?";
        let current_word = match tx.query_row(
            select_query,
            [rusqlite::types::Value::Blob(ga.to_vec())],
            |row| row.get::<_, Self::Word>(0),
        ) {
            Ok(word) => Some(word),
            // No rows returned means the address is not in the database
            // This is an expected scenario and its result is `None`
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => {
                tx.rollback()?;
                return Err(SqlMemoryError::SqlError(e));
            }
        };

        if current_word == gw {
            // guard passed, flatten bindings
            let args = params_from_iter(bindings.iter().flat_map(|(a, w)| {
                vec![
                    rusqlite::types::Value::Blob(a.to_vec()),
                    rusqlite::types::Value::Blob(w.to_vec()),
                ]
            }));
            let insert_query = "INSERT OR REPLACE INTO memory (a, w) VALUES ".to_owned()
                + &(0..bindings.len())
                    .map(|_| "(?,?)")
                    .collect::<Vec<&str>>()
                    .join(",");
            let insert_count = tx.execute(&insert_query, args)?;
            if insert_count == bindings.len() {
                tx.commit()?;
                return Ok(current_word);
            } else {
                tx.rollback()?;
                return Err(SqlMemoryError::SqlError(
                    rusqlite::Error::StatementChangedRows(insert_count),
                ));
            }
        } else {
            return Ok(current_word);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        ADDRESS_LENGTH, WORD_LENGTH,
        adt::test_utils::{
            test_guarded_write_concurrent, test_single_write_and_read, test_wrong_guard,
        },
    };

    #[tokio::test]
    async fn test_rw_seq() -> Result<(), SqlMemoryError> {
        let m = SqlMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::in_memory(None)?;
        test_single_write_and_read(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), SqlMemoryError> {
        let m = SqlMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::in_memory(None)?;
        test_wrong_guard(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), SqlMemoryError> {
        let m = SqlMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::in_memory(None)?;
        test_guarded_write_concurrent(&m, rand::random()).await;
        Ok(())
    }
}
