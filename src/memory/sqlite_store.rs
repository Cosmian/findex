use crate::{Address, MemoryADT};
use async_sqlite::{
    Pool, PoolBuilder,
    rusqlite::{OptionalExtension, params_from_iter},
};
use std::{
    collections::HashMap,
    fmt::{self, Debug},
    marker::PhantomData,
    ops::Deref,
};

#[derive(Debug)]
pub enum SqliteMemoryError {
    AsyncSqliteError(async_sqlite::Error),
}

impl std::error::Error for SqliteMemoryError {}

impl fmt::Display for SqliteMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AsyncSqliteError(err) => write!(f, "async-sqlite error: {}", err),
        }
    }
}

impl From<async_sqlite::Error> for SqliteMemoryError {
    fn from(err: async_sqlite::Error) -> Self {
        Self::AsyncSqliteError(err)
    }
}

pub const FINDEX_TABLE_NAME: &str = "findex_memory";
#[derive(Clone)]
pub struct SqliteMemory<Address, Word> {
    pool: Pool,
    _marker: PhantomData<(Address, Word)>,
}

impl<Address, Word> Debug for SqliteMemory<Address, Word> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteMemory")
            .field("pool", &"<async_sqlite::Pool>")
            .field("_marker", &PhantomData::<(Address, Word)>)
            .finish()
    }
}

// The following settings are used to improve performance:
// - journal_mode = WAL : WAL journaling is faster than the default DELETE mode.
// - synchronous = NORMAL: Reduces disk I/O by only calling fsync() at critical
//   moments rather than after every transaction (FULL mode); this does not
//   compromise data integrity.
fn create_table_script(table_name: &str) -> String {
    format!(
        "
PRAGMA synchronous = NORMAL;
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS {} (
    a BLOB PRIMARY KEY,
    w BLOB NOT NULL
);",
        table_name
    )
}

impl<Address, Word> SqliteMemory<Address, Word> {
    /// Builds a pool connected to a known DB (using the given path) and creates
    /// the `findex_memory` table.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the sqlite3 database file.
    pub async fn connect(path: &str) -> Result<Self, SqliteMemoryError> {
        // The number of connections in this pools defaults to the number of
        // logical CPUs of the system.
        let pool = PoolBuilder::new().path(path).open().await?;

        pool.conn(|conn| conn.execute_batch(&create_table_script(FINDEX_TABLE_NAME)))
            .await?;

        Ok(Self {
            pool,
            _marker: PhantomData,
        })
    }

    /// Returns an `SqliteMemory` instance storing data in a table with the given name
    /// and connecting to the DB using connections from the given pool.
    ///
    /// # Arguments
    ///
    /// * `pool` - The pool to use for the memory.
    /// * `table_name` - The name of the table to create.
    pub async fn connect_with_pool(
        pool: Pool,
        table_name: String,
    ) -> Result<Self, SqliteMemoryError> {
        pool.conn(move |conn| conn.execute_batch(&create_table_script(&table_name)))
            .await?;
        Ok(Self {
            pool,
            _marker: PhantomData,
        })
    }
}

impl<Address: Send + Sync, Word: Send + Sync> SqliteMemory<Address, Word> {
    #[cfg(feature = "test-utils")]
    pub async fn clear(&self) -> Result<(), SqliteMemoryError> {
        self.pool
            .conn(|cnx| cnx.execute(&format!("DELETE FROM {FINDEX_TABLE_NAME}"), []))
            .await?;
        Ok(())
    }
}

impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize> MemoryADT
    for SqliteMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    type Address = Address<ADDRESS_LENGTH>;
    type Error = SqliteMemoryError;
    type Word = [u8; WORD_LENGTH];

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        self.pool
            .conn(move |conn| {
                let results = conn
                    .prepare(&format!(
                        "SELECT a, w FROM {} WHERE a IN ({})",
                        FINDEX_TABLE_NAME,
                        vec!["?"; addresses.len()].join(",")
                    ))?
                    .query_map(
                        params_from_iter(addresses.iter().map(Deref::deref)),
                        |row| {
                            let a = Address::from(row.get::<_, [u8; ADDRESS_LENGTH]>(0)?);
                            let w = row.get(1)?;
                            Ok((a, w))
                        },
                    )?
                    .collect::<Result<HashMap<_, _>, _>>()?;

                // Return order of an SQL select statement is undefined, and
                // mismatches are ignored. A post-processing is thus needed to
                // generate a returned value complying to the batch-read spec.
                Ok(addresses
                    .iter()
                    // Copying is necessary here since the same word could be
                    // returned multiple times.
                    .map(|addr| results.get(addr).copied())
                    .collect())
            })
            .await
            .map_err(Self::Error::from)
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let (ag, wg) = guard;

        self.pool
            .conn_mut(move |conn| {
                let tx = conn.transaction_with_behavior(
                    async_sqlite::rusqlite::TransactionBehavior::Immediate,
                )?;

                let current_word = tx
                    .query_row(
                        &format!("SELECT w FROM {} WHERE a = ?", FINDEX_TABLE_NAME),
                        [&*ag],
                        |row| row.get(0),
                    )
                    .optional()?;

                if current_word == wg {
                    tx.execute(
                        &format!(
                            "INSERT OR REPLACE INTO {} (a, w) VALUES {}",
                            FINDEX_TABLE_NAME,
                            vec!["(?,?)"; bindings.len()].join(",")
                        ),
                        params_from_iter(
                            bindings
                                .iter()
                                // There seems to be no way to avoid cloning here.
                                .flat_map(|(a, w)| [a.to_vec(), w.to_vec()]),
                        ),
                    )?;
                    tx.commit()?;
                }

                Ok(current_word)
            })
            .await
            .map_err(Self::Error::from)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        WORD_LENGTH, gen_seed, test_guarded_write_concurrent, test_rw_same_address,
        test_single_write_and_read, test_wrong_guard,
    };

    const DB_PATH: &str = "./target/debug/sqlite-test.db";

    #[tokio::test]
    async fn test_rw_seq() {
        let m = SqliteMemory::<_, [u8; WORD_LENGTH]>::connect(DB_PATH)
            .await
            .unwrap();
        test_single_write_and_read(&m, gen_seed()).await
    }

    #[tokio::test]
    async fn test_guard_seq() {
        let m = SqliteMemory::<_, [u8; WORD_LENGTH]>::connect(DB_PATH)
            .await
            .unwrap();
        test_wrong_guard(&m, gen_seed()).await
    }

    #[tokio::test]
    async fn test_collision_seq() {
        let m = SqliteMemory::<_, [u8; WORD_LENGTH]>::connect(DB_PATH)
            .await
            .unwrap();
        test_rw_same_address(&m, gen_seed()).await
    }

    #[tokio::test]
    async fn test_rw_ccr() {
        let m = SqliteMemory::<_, [u8; WORD_LENGTH]>::connect(DB_PATH)
            .await
            .unwrap();
        test_guarded_write_concurrent(&m, gen_seed(), Some(100)).await
    }
}
