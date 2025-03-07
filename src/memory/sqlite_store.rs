use crate::{Address, MemoryADT};
use async_sqlite::{JournalMode, Pool, PoolBuilder};
use rusqlite::{OptionalExtension, params_from_iter, types::Value::Blob};
use std::{
    collections::HashMap,
    fmt::{self, Debug},
    marker::PhantomData,
    ops::Deref,
    path::Path,
    sync::Arc,
};

#[derive(Debug)]
pub enum SqliteMemoryError {
    SqlError(rusqlite::Error),
    PoolingError(r2d2::Error),
    AsyncSqliteError(async_sqlite::Error),
}

impl std::error::Error for SqliteMemoryError {}

impl fmt::Display for SqliteMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SqlError(err) => write!(f, "Sql store memory error: {}", err),
            Self::PoolingError(err) => write!(f, "r2d2 pooling error: {}", err),
            Self::AsyncSqliteError(err) => write!(f, "async-sqlite error: {}", err),
        }
    }
}

impl From<rusqlite::Error> for SqliteMemoryError {
    fn from(err: rusqlite::Error) -> Self {
        Self::SqlError(err)
    }
}

impl From<r2d2::Error> for SqliteMemoryError {
    fn from(err: r2d2::Error) -> Self {
        Self::PoolingError(err)
    }
}

impl From<async_sqlite::Error> for SqliteMemoryError {
    fn from(err: async_sqlite::Error) -> Self {
        Self::AsyncSqliteError(err)
    }
}

// TODO : mix pragma and wal calls
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

const CREATE_TABLE_SCRIPT: &str = "PRAGMA synchronous = NORMAL;
CREATE TABLE IF NOT EXISTS memory (
    a BLOB PRIMARY KEY,
    w BLOB NOT NULL
);";

impl<Address, Word> SqliteMemory<Address, Word> {
    /// Connects to a known DB using the given path.
    pub async fn connect(path: &str) -> Result<Self, SqliteMemoryError> {
        // SqliteConnectionManager::file is the equivalent of using
        // `rusqlite::Connection::open` as documented in the function's source
        // code. Two pragmas are set to drastically improve performance :
        // - journal_mode = WAL : WAL journaling is faster than the default DELETE mode without compromising reliability as it
        //   safe from corruption with synchronous=NORMAL
        // - synchronous = NORMAL : fsync only in critical moments, drastically improving performance as
        //   fsync is a very expensive operation.
        let pool = PoolBuilder::new()
            .path(path)
            .journal_mode(JournalMode::Wal)
            .open()
            .await
            .unwrap();

        pool.conn(|conn| conn.execute_batch(CREATE_TABLE_SCRIPT))
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
        let adr_arc = Arc::new(addresses);
        let adr_arc_clone = Arc::clone(&adr_arc);

        let mut bindings = self
            .pool
            .conn(move |conn| {
                conn.prepare(&format!(
                    "SELECT a, w FROM memory WHERE a IN ({})",
                    vec!["?"; adr_arc_clone.len()].join(",")
                ))?
                .query_map(
                    params_from_iter(adr_arc_clone.iter().map(Deref::deref)),
                    |row| {
                        let a = Address::from(row.get::<_, [u8; ADDRESS_LENGTH]>(0)?);
                        let w = row.get(1)?;
                        Ok((a, w))
                    },
                )?
                .collect::<Result<HashMap<_, _>, _>>()
            })
            .await?;

        // Return order of an SQL select statement is undefined, and
        // mismatched are ignored. A post-processing is thus needed to
        // generate a returned value complying to the batch-read spec.
        Ok(adr_arc.iter().map(|addr| bindings.remove(addr)).collect())
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let (ag, wg) = guard;

        let current_word = self
            .pool
            .conn_mut(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

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
                                .flat_map(|(a, w)| [Blob(a.to_vec()), Blob(w.to_vec())]),
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

    const DB_PATH: &str = "./sqlite.db";

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
    async fn test_rw_ccr() -> Result<(), SqliteMemoryError> {
        let m =
            SqliteMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect(DB_PATH).await?;
        test_guarded_write_concurrent(&m, rand::random(), Some(100)).await;
        Ok(())
    }
}
