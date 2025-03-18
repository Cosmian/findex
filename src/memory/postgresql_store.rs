use crate::{Address, MemoryADT};
use deadpool_postgres::{Config, CreatePoolError, Runtime};
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio_postgres::{Client, Connection, NoTls, Socket, Statement, tls::MakeTlsConnect};

#[derive(Debug)]
pub enum PostgresMemoryError {
    AsyncPostgresError(tokio_postgres::Error),
    TryFromSliceError(std::array::TryFromSliceError),
    CreatePoolError(deadpool_postgres::CreatePoolError),
    TableCreationError(u64),
    InvalidDataLength(usize),
}

impl std::error::Error for PostgresMemoryError {}

impl fmt::Display for PostgresMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AsyncPostgresError(err) => write!(f, "async-postgres error: {}", err),
            Self::TryFromSliceError(err) => write!(f, "try_from_slice error: {}", err),
            Self::TableCreationError(rows) => {
                write!(
                    f,
                    "table creation returned unexpected row count: {}. Expected 0 rows.",
                    rows
                )
            }
            Self::InvalidDataLength(len) => {
                write!(
                    f,
                    "invalid data length: received {} bytes from db instead of WORD_LENGTH bytes",
                    len
                )
            }
            Self::CreatePoolError(err) => write!(f, "deadpool_postgres error: {}", err),
        }
    }
}

impl From<CreatePoolError> for PostgresMemoryError {
    fn from(err: CreatePoolError) -> Self {
        Self::CreatePoolError(err)
    }
}

impl From<tokio_postgres::Error> for PostgresMemoryError {
    fn from(err: tokio_postgres::Error) -> Self {
        Self::AsyncPostgresError(err)
    }
}

impl From<std::array::TryFromSliceError> for PostgresMemoryError {
    fn from(err: std::array::TryFromSliceError) -> Self {
        Self::TryFromSliceError(err)
    }
}

#[derive(Clone, Debug)]
pub struct PostGresMemory<Address, Word> {
    client: Arc<Client>,
    select_stmt: Arc<Statement>,
    insert_stmt: Arc<Statement>,
    _marker: PhantomData<(Address, Word)>,
}

const B_READ_STMT: &str = "
    SELECT f.w
    FROM UNNEST($1::bytea[]) WITH ORDINALITY AS params(addr, idx)
    LEFT JOIN findex_db f ON params.addr = f.a
    ORDER BY params.idx;
";

const G_WRITE_STMT: &str = "
    WITH
    guard_check AS (
        SELECT w FROM findex_db WHERE a = $1::bytea
    ),
    dedup_input_table AS (
    SELECT DISTINCT ON (a) a, w
        FROM UNNEST($3::bytea[], $4::bytea[]) WITH ORDINALITY AS t(a, w, order_idx)
        ORDER BY a, order_idx DESC),
    insert_cte AS (
    INSERT INTO findex_db (a, w)
    SELECT a, w FROM dedup_input_table AS t(a,w)
    WHERE (
        $2::bytea IS NULL AND NOT EXISTS (SELECT 1 FROM guard_check)
    ) OR (
        $2::bytea IS NOT NULL AND EXISTS (
            SELECT 1 FROM guard_check WHERE w = $2::bytea
        )
    )
    ON CONFLICT (a) DO UPDATE SET w = EXCLUDED.w
    )
    SELECT COALESCE((SELECT w FROM guard_check)) AS original_guard_value;
";

impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize>
    PostGresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    pub async fn connect<T>(
        client: Client,
        connection: Connection<Socket, T::Stream>,
    ) -> Result<Self, PostgresMemoryError>
    where
        T: MakeTlsConnect<Socket>,
        T::Stream: Send + 'static, // 'static bound simply ensures that the type is fully owned
    {
        // The connection object performs the actual communication with the database
        // `Connection` only resolves when the connection is closed, either because a fatal error has
        // occurred, or because its associated `Client` has dropped and all outstanding work has completed.
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });

        let returned = client
            .execute(
                &format!(
                    "
                    CREATE TABLE IF NOT EXISTS findex_db (
                        a BYTEA PRIMARY KEY CHECK (octet_length(a) = {}),
                        w BYTEA NOT NULL CHECK (octet_length(w) = {})
                    );",
                    ADDRESS_LENGTH, WORD_LENGTH
                ),
                &[],
            )
            .await?;
        if returned != 0 {
            return Err(PostgresMemoryError::TableCreationError(returned));
        }

        let _ = client
            .execute(
                "
                ALTER TABLE findex_db
                ALTER COLUMN a SET STORAGE EXTERNAL,
                ALTER COLUMN w SET STORAGE EXTERNAL;",
                &[],
            )
            .await?;
        let select_stmt = client.prepare(B_READ_STMT).await?;
        let insert_stmt = client.prepare(G_WRITE_STMT).await?;

        Ok(Self {
            client: Arc::new(client),
            select_stmt: Arc::new(select_stmt),
            insert_stmt: Arc::new(insert_stmt),
            _marker: PhantomData,
        })
    }

    pub async fn connect_with_pool<T>(url: &str) -> Result<Self, PostgresMemoryError>
    where
        T: MakeTlsConnect<Socket>,
        T::Stream: Send + 'static, // 'static bound simply ensures that the type is fully owned
    {
        let mut cfg = Config::new();
        cfg.url = Some("postgres://cosmian_findex:cosmian_findex@localhost/cosmian?application_name=findex_rust&sslmode=prefer".to_string());
        let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls)?;
        let client = pool.get().await.unwrap(); // TODO not in prod !!!

        let returned = client
            .execute(
                &format!(
                    "
                    CREATE TABLE IF NOT EXISTS findex_db (
                        a BYTEA PRIMARY KEY CHECK (octet_length(a) = {}),
                        w BYTEA NOT NULL CHECK (octet_length(w) = {})
                    );",
                    ADDRESS_LENGTH, WORD_LENGTH
                ),
                &[],
            )
            .await?;
        if returned != 0 {
            return Err(PostgresMemoryError::TableCreationError(returned));
        }

        let _ = client
            .execute(
                "
                ALTER TABLE findex_db
                ALTER COLUMN a SET STORAGE EXTERNAL,
                ALTER COLUMN w SET STORAGE EXTERNAL;",
                &[],
            )
            .await?;
        let select_stmt = client.prepare(B_READ_STMT).await?;
        let insert_stmt = client.prepare(G_WRITE_STMT).await?;

        Ok(Self {
            client: Arc::new(client),
            select_stmt: Arc::new(select_stmt),
            insert_stmt: Arc::new(insert_stmt),
            _marker: PhantomData,
        })
    }

    /// Use this method to disconnect from the database before program termination.
    pub async fn disconnect(self) -> Result<(), PostgresMemoryError> {
        Ok(drop(self))
    }
}

impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize> MemoryADT
    for PostGresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    type Address = Address<ADDRESS_LENGTH>;
    type Word = [u8; WORD_LENGTH];
    type Error = PostgresMemoryError;

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        self.client
            // the left join is necessary to ensure that the order of the addresses is preserved
            // as well as to return None for addresses that don't exist
            .query(&*self.select_stmt, &[&addresses
                .iter()
                .map(|addr| addr.as_slice())
                .collect::<Vec<_>>()])
            .await?
            .iter()
            .map(|row| {
                let bytes_slice: Option<&[u8]> = row.try_get("w")?; // `row.get(0)` can panic
                bytes_slice.map_or(Ok(None), |slice| {
                    slice
                        .try_into()
                        .map(Some)
                        .map_err(|_| PostgresMemoryError::InvalidDataLength(slice.len()))
                })
            })
            .collect::<Result<Vec<_>, Self::Error>>()
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        if bindings.len() == 0 {
            // When PostgreSQL encounters a VALUES clause with nothing inside it it will throw a syntax error.
            return self
                .batch_read(vec![guard.0])
                .await
                .map(|v| v.into_iter().next().flatten());
        }

        let (addresses, words): (Vec<[u8; ADDRESS_LENGTH]>, Vec<Self::Word>) =
            bindings.into_iter().map(|(a, w)| (*a, w)).unzip();

        self.client
            .query_opt(&*self.insert_stmt, &[
                &*guard.0,
                match &guard.1 {
                    Some(g) => g,
                    None => &None::<&[u8]>,
                },
                &addresses,
                &words,
            ])
            .await?
            .map_or(Ok(None), |row| {
                row.try_get::<_, Option<&[u8]>>(0)?
                    .map(|b| b.try_into())
                    .map_or(Ok(None), |r| Ok(Some(r?)))
            })
    }
}

#[cfg(test)]
mod tests {
    use tokio_postgres::NoTls;

    use super::*;
    use crate::{
        ADDRESS_LENGTH, Address, WORD_LENGTH,
        adt::test_utils::{
            test_collisions, test_guarded_write_concurrent, test_single_write_and_read,
            test_wrong_guard,
        },
    };

    const DB_URI: &str = "postgres://cosmian_findex:cosmian_findex@localhost/cosmian?application_name=findex_rust&sslmode=prefer";

    #[tokio::test]
    async fn test_rw_seq() -> Result<(), PostgresMemoryError> {
        let (client, connection) = tokio_postgres::connect(DB_URI, NoTls).await?;
        let m = PostGresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect::<NoTls>(
            client, connection,
        )
        .await?;
        test_single_write_and_read::<WORD_LENGTH, _>(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), PostgresMemoryError> {
        let (client, connection) = tokio_postgres::connect(DB_URI, NoTls).await?;
        let m = PostGresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect::<NoTls>(
            client, connection,
        )
        .await?;
        test_wrong_guard::<WORD_LENGTH, _>(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_collision_seq() -> Result<(), PostgresMemoryError> {
        let (client, connection) = tokio_postgres::connect(DB_URI, NoTls).await?;
        let m = PostGresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect::<NoTls>(
            client, connection,
        )
        .await?;
        test_collisions::<WORD_LENGTH, _>(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), PostgresMemoryError> {
        let (client, connection) = tokio_postgres::connect(DB_URI, NoTls).await?;
        let m = PostGresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect::<NoTls>(
            client, connection,
        )
        .await?;
        test_guarded_write_concurrent(&m, rand::random(), Some(1000)).await;
        Ok(())
    }
}
