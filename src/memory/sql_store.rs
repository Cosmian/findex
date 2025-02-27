use crate::{Address, MemoryADT};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params_from_iter, types::ToSqlOutput};
use std::marker::PhantomData;
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
    pub fn in_memory() -> Result<Self, SqlMemoryError> {
        let pool = r2d2::Pool::builder()
            .max_size(MAX_POOL_SIZE)
            .build(SqliteConnectionManager::memory())?;
        pool.get().unwrap().execute(CREATE_TABLE_SCRIPT, [])?;
        Ok(Self {
            pool,
            _marker: PhantomData,
        })
    }

    /// Connects to a known DB url using the given URL.
    pub fn connect(url: &str) -> Result<Self, SqlMemoryError> {
        // SqliteConnectionManager::file is the equivalent of using `rusqlite::Connection::open`
        // as documented in the function's source code.
        let pool = r2d2::Pool::builder()
            .max_size(MAX_POOL_SIZE)
            .build(SqliteConnectionManager::file(url))?;
        pool.get().unwrap().execute(CREATE_TABLE_SCRIPT, [])?;

        Ok(Self {
            pool,
            _marker: PhantomData,
        })
    }
}

impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize> MemoryADT
    for SqlMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    type Address = Address<ADDRESS_LENGTH>;
    type Word = [u8; WORD_LENGTH];
    type Error = SqlMemoryError;

    // TODO: IMPORTANT! call tokio::task::spawn_blocking because rusqlite is blocking
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
        // todo!("Implement guarded_write for sql_store");
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;

        let (guard_address, guard_value) = guard;

        let first_query = "SELECT word AS previous_value FROM findex_aw_store WHERE adr = ?";
        // Convert addresses to SQL parameters
        let first_query_res: Result<[u8; WORD_LENGTH], rusqlite::Error> = tx.query_row(
            first_query,
            [rusqlite::types::Value::Blob(guard_address.to_vec())],
            |row| row.get(0),
        );
        #[allow(clippy::option_if_let_else)] // TODO: will fix this later
        let previous_word = if let Ok(item) = first_query_res {
            Some(item)
        } else {
            None
        };
        if previous_word == guard_value {
            // flatten bindings
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
                Ok(previous_word)
            } else {
                // TODO!: should we put a loop ?
                tx.rollback()?;
                Err(SqlMemoryError::SqlError(
                    rusqlite::Error::ExecuteReturnedResults,
                ))
            }
        } else {
            // tx.rollback()?;
            Ok(previous_word)
        }
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
        let m = SqlMemory::in_memory()?;
        test_single_write_and_read(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), SqlMemoryError> {
        let m = SqlMemory::in_memory()?;
        test_wrong_guard(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), SqlMemoryError> {
        let m = SqlMemory::in_memory()?;
        test_guarded_write_concurrent(&m, rand::random()).await;
        Ok(())
    }
}
