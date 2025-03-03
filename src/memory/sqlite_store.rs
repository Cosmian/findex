use std::{marker::PhantomData, thread::sleep, time::Duration};

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params_from_iter, types::ToSqlOutput};
use thiserror::Error;

use crate::{Address, MemoryADT};

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

const MAX_POOL_SIZE: u32 = 10; // placeholder
const CREATE_TABLE_SCRIPT: &str = "
CREATE TABLE IF NOT EXISTS findex_aw_store
(
    adr BLOB PRIMARY KEY,
    word BLOB NOT NULL
)";

impl<Address: Sync, Word: Sync> SqlMemory<Address, Word> {
    /// Create a new in-memory database.
    pub fn in_memory(backoff: Option<bool>) -> Result<Self, SqlMemoryError> {
        let pool = r2d2::Pool::builder()
            .max_size(MAX_POOL_SIZE)
            .build(SqliteConnectionManager::memory())?;
        pool.get().unwrap().execute(CREATE_TABLE_SCRIPT, [])?;
        Ok(Self {
            pool,
            exponential_backoff: backoff.unwrap_or(false),
            _marker: PhantomData,
        })
    }

    /// Connects to a known DB url using the given URL.
    pub fn connect(url: &str, backoff: Option<bool>) -> Result<Self, SqlMemoryError> {
        // SqliteConnectionManager::file is the equivalent of using
        // `rusqlite::Connection::open` as documented in the function's source
        // code.
        let pool = r2d2::Pool::builder()
            .max_size(MAX_POOL_SIZE)
            .build(SqliteConnectionManager::file(url))?;
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
        let mut conn = self.pool.get()?;

        // Using a transaction to ensure the read is atomic
        let tx = conn.transaction()?;

        let query = format!(
            "SELECT adr, word FROM findex_aw_store WHERE adr IN ({})",
            (0..addresses.len())
                .map(|_| "?")
                .collect::<Vec<&str>>()
                .join(",")
        );

        // Convert addresses to SQL parameters
        let params: Vec<ToSqlOutput> = addresses
            .iter()
            .map(|addr| {
                rusqlite::types::ToSqlOutput::Borrowed(rusqlite::types::ValueRef::Blob(&**addr))
            })
            .collect();

        // Execute the query
        let mut stmt = tx.prepare(&query)?;
        let mut rows = stmt.query(rusqlite::params_from_iter(params))?;

        // Process all rows
        let mut result_map = std::collections::HashMap::new();
        while let Some(row) = rows.next()? {
            let adr: Self::Address = row.get::<_, [u8; ADDRESS_LENGTH]>(0)?.into();
            let word: Self::Word = row.get(1)?; // tb verified
            // Convert to fixed-size array
            result_map.insert(adr, word);
        }

        // Create results in the same order as input addresses
        // TODO: Check if this is necessary of if the order is always respected anyway
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

        let (guard_address, guard_value) = guard;

        let max_retries = 5;
        // start with a very small delay since SQLite is used locally
        // only used if exponential_backoff is enabled
        let base_delay_ms = 2;
        let mut retries = 0;
        let mut last_err = rusqlite::Error::ExecuteReturnedResults;

        while retries < max_retries {
            if self.exponential_backoff && retries > 0 {
                sleep(Duration::from_millis(base_delay_ms * 2_u64.pow(retries)));
            }
            retries += 1;
            let tx = conn.transaction()?;
            let first_query = "SELECT word AS previous_value FROM findex_aw_store WHERE adr = ?";
            // Convert addresses to SQL parameters
            let previous_word = match tx.query_row(
                first_query,
                [rusqlite::types::Value::Blob(guard_address.to_vec())],
                |row| row.get::<_, Self::Word>(0),
            ) {
                Ok(word) => Some(word),
                // No rows returned, the address is not in the database
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => {
                    tx.rollback()?;
                    last_err = e;
                    continue; // Continue retry loop
                }
            };

            if previous_word == guard_value {
                // guard passed, flatten bindings
                let params2 = params_from_iter(bindings.iter().flat_map(|(a, w)| {
                    vec![
                        rusqlite::types::Value::Blob(a.to_vec()),
                        rusqlite::types::Value::Blob(w.to_vec()),
                    ]
                }));
                let pts_dinterrogation = (0..bindings.len())
                    .map(|_| "(?,?)")
                    .collect::<Vec<&str>>()
                    .join(",");
                let second_query = "INSERT OR REPLACE INTO findex_aw_store (adr, word) VALUES "
                    .to_owned()
                    + &pts_dinterrogation;
                let r = tx.execute(&second_query, params2)?;
                if r == bindings.len() {
                    tx.commit()?;
                    return Ok(previous_word);
                } else {
                    last_err = rusqlite::Error::StatementChangedRows(bindings.len());
                    tx.rollback()?;
                }
            } else {
                return Ok(previous_word);
            }
        }
        // TODO: feature, ideally this should return a stack of all the errors that made
        // the transaction fail
        Err(SqlMemoryError::SqlError(last_err))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::adt::test_utils::{
        test_guarded_write_concurrent, test_single_write_and_read, test_wrong_guard,
    };

    #[tokio::test]
    async fn test_rw_seq() -> Result<(), SqlMemoryError> {
        let m = SqlMemory::in_memory(None)?;
        test_single_write_and_read(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), SqlMemoryError> {
        let m = SqlMemory::in_memory(None)?;
        test_wrong_guard(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), SqlMemoryError> {
        let m = SqlMemory::in_memory(None)?;
        test_guarded_write_concurrent(&m, rand::random()).await;
        Ok(())
    }
}
