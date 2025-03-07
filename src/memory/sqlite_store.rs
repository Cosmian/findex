use crate::{Address, MemoryADT};
use async_sqlite::{
    JournalMode, Pool, PoolBuilder,
    rusqlite::{OptionalExtension, params_from_iter},
};
use std::{
    collections::HashMap,
    fmt::{self, Debug},
    marker::PhantomData,
    ops::Deref,
    sync::Arc,
    time::Duration,
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

#[derive(Clone)]
pub struct SqliteMemory<Address, Word> {
    pool: Pool,
    timeout: Duration,
    _marker: PhantomData<(Address, Word)>,
}

impl<Address, Word> Debug for SqliteMemory<Address, Word> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteMemory")
            .field("pool", &"<async_sqlite::Pool>")
            .field("timeout", &self.timeout)
            .field("_marker", &PhantomData::<(Address, Word)>)
            .finish()
    }
}

const CREATE_TABLE_SCRIPT: &str = "PRAGMA synchronous = NORMAL;
CREATE TABLE IF NOT EXISTS memory (
    a BLOB PRIMARY KEY,
    w BLOB NOT NULL
);";

// 5 seconds is the current default timeout for sqlite3 busy handlers.
const TIMEOUT_DURATION_MS: u64 = 5000;

impl<Address, Word> SqliteMemory<Address, Word> {
    /// Connects to a known DB using the given path.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the sqlite3 database file.
    /// * `timeout` - Optional : the timeout for the busy handler in milliseconds, to be only changed if necessary.
    pub async fn connect(path: &str, timeout: Option<Duration>) -> Result<Self, SqliteMemoryError> {
        // This pool connections number defaults to the number of logical CPUs of the current system.
        // The following settings are used to improve performance:
        // - journal_mode = WAL : WAL journaling is faster than the default DELETE mode without compromising reliability
        // - synchronous = NORMAL : makes calling the (expensive) `fsync` only done in critical moments
        let pool = PoolBuilder::new()
            .path(path)
            .journal_mode(JournalMode::Wal)
            .open()
            .await?;

        let timeout = timeout.unwrap_or(Duration::from_millis(TIMEOUT_DURATION_MS));

        pool.conn_mut(move |conn| {
            conn.busy_timeout(timeout)?;
            conn.execute_batch(CREATE_TABLE_SCRIPT)
        })
        .await?;

        Ok(Self {
            pool,
            timeout,
            _marker: PhantomData,
        })
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
        let res = self
            .pool
            .conn_mut(move |conn| {
                let mut bindings = conn
                    .prepare(&format!(
                        "SELECT a, w FROM memory WHERE a IN ({})",
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
                // mismatched are ignored. A post-processing is thus needed to
                // generate a returned value complying to the batch-read spec.
                Ok(addresses.iter().map(|addr| bindings.remove(addr)).collect())
            })
            .await?;
        Ok(res)
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let (ag, wg) = guard;
        let duration = Arc::new(self.timeout);

        let current_word = self
            .pool
            .conn_mut(move |conn| {
                let tx = conn.transaction_with_behavior(
                    async_sqlite::rusqlite::TransactionBehavior::Immediate,
                )?;
                tx.busy_timeout(*duration)?; // 30s

                let current_word = tx
                    .query_row("SELECT w FROM memory WHERE a = ?", [&*ag], |row| row.get(0))
                    .optional()?;

                if current_word == wg {
                    tx.execute(
                        &format!(
                            "INSERT OR REPLACE INTO memory (a, w) VALUES {}",
                            vec!["(?,?)"; bindings.len()].join(",")
                        ),
                        params_from_iter(
                            bindings
                                .iter()
                                // There seems to be no way to avoid cloning here.
                                // Wrapping a and w in `Blob` can be avoiding as the underlying structure is the same.
                                .flat_map(|(a, w)| [a.to_vec(), w.to_vec()]),
                        ),
                    )?;
                    tx.commit()?;
                }

                Ok(current_word)
            })
            .await?;

        Ok(current_word)
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

    const DB_PATH: &str = "./target/debug/sqlite-test.db";

    #[tokio::test]
    async fn test_rw_seq() -> Result<(), SqliteMemoryError> {
        let m = SqliteMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect(DB_PATH, None)
            .await?;
        test_single_write_and_read(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), SqliteMemoryError> {
        let m = SqliteMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect(DB_PATH, None)
            .await?;
        test_wrong_guard(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), SqliteMemoryError> {
        let m = SqliteMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect(DB_PATH, None)
            .await?;
        test_guarded_write_concurrent(&m, rand::random(), Some(100)).await;
        Ok(())
    }
}
