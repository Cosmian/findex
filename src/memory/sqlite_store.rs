use crate::{Address, MemoryADT};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{OptionalExtension, params_from_iter, types::Value::Blob};
use std::{collections::HashMap, fmt, marker::PhantomData, ops::Deref, path::Path};

#[derive(Debug)]
pub enum SqliteMemoryError {
    SqlError(rusqlite::Error),
    PoolingError(r2d2::Error),
}

impl std::error::Error for SqliteMemoryError {}

impl fmt::Display for SqliteMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SqlError(err) => write!(f, "Sql store memory error: {}", err),
            Self::PoolingError(err) => write!(f, "r2d2 pooling error: {}", err),
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

#[derive(Debug, Clone)]
pub struct SqliteMemory<Address, Word> {
    pool: Pool<SqliteConnectionManager>,
    _marker: PhantomData<(Address, Word)>,
}

const CREATE_TABLE_SCRIPT: &str = "
CREATE TABLE IF NOT EXISTS memory
(
    a BLOB PRIMARY KEY,
    w BLOB NOT NULL
)";

impl<Address, Word> SqliteMemory<Address, Word> {
    /// Connects to a known DB using the given path.
    pub fn connect(path: &impl AsRef<Path>) -> Result<Self, SqliteMemoryError> {
        // SqliteConnectionManager::file is the equivalent of using
        // `rusqlite::Connection::open` as documented in the function's source
        // code.
        let pool = r2d2::Pool::builder().build(SqliteConnectionManager::file(path))?;
        pool.get().unwrap().execute(CREATE_TABLE_SCRIPT, [])?;

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
        let conn = self.pool.get()?;

        // Return order of an SQL select statement is undefined, and
        // mismatched are ignored. A post-processing is thus needed to
        // generate a returned value complying to the batch-read spec.
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

        Ok(addresses.iter().map(|addr| bindings.remove(addr)).collect())
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let (ag, wg) = guard;

        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;

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
                    // There seems to be no way to avoid cloning here.
                    bindings
                        .iter()
                        .flat_map(|(a, w)| [Blob(a.to_vec()), Blob(w.to_vec())]),
                ),
            )?;
            tx.commit()?;
        }

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
        let m = SqliteMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect(&Path::new(
            DB_PATH,
        ))?;
        test_single_write_and_read(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), SqliteMemoryError> {
        let m = SqliteMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect(&Path::new(
            DB_PATH,
        ))?;
        test_wrong_guard(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), SqliteMemoryError> {
        let m = SqliteMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect(&Path::new(
            DB_PATH,
        ))?;
        test_guarded_write_concurrent(&m, rand::random(), None).await;
        Ok(())
    }
}
