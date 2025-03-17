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
// - synchronous = NORMAL: Reduces disk I/O by only calling fsync() at critical moments rather
//   than after every transaction (FULL mode); this does not compromise data integrity.
const CREATE_TABLE_SCRIPT: &str = "
PRAGMA synchronous = NORMAL;
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS memory (
    a BLOB PRIMARY KEY,
    w BLOB NOT NULL
);";

impl<Address, Word> SqliteMemory<Address, Word> {
    /// Connects to a known DB using the given path.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the sqlite3 database file.
    pub async fn connect(path: &str) -> Result<Self, SqliteMemoryError> {
        // This pool connections number defaults to the number of logical CPUs of the current system.
        let pool = PoolBuilder::new().path(path).open().await?;

        pool.conn(move |conn| conn.execute_batch(CREATE_TABLE_SCRIPT))
            .await?;

        Ok(Self {
            pool,
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
        self.pool
            .conn(move |conn| {
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
                // mismatches are ignored. A post-processing is thus needed to
                // generate a returned value complying to the batch-read spec.
                Ok(addresses.iter().map(|addr| bindings.remove(addr)).collect())
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
        ADDRESS_LENGTH, WORD_LENGTH,
        adt::test_utils::{
            test_collisions, test_guarded_write_concurrent, test_single_write_and_read,
            test_wrong_guard,
        },
    };

    const DB_PATH: &str = "./target/debug/sqlite-test.db";

    #[tokio::test]
    async fn test_rw_seq() -> Result<(), SqliteMemoryError> {
        let m =
            SqliteMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect(DB_PATH).await?;
        test_single_write_and_read(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), SqliteMemoryError> {
        let m =
            SqliteMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect(DB_PATH).await?;
        test_wrong_guard(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_collision_seq() -> Result<(), SqliteMemoryError> {
        let m =
            SqliteMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect(DB_PATH).await?;
        test_collisions(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), SqliteMemoryError> {
        let m =
            SqliteMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect(DB_PATH).await?;
        test_guarded_write_concurrent(&m, rand::random(), Some(100)).await;
        Ok(())
    }
}
