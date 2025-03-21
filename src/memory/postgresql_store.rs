use crate::{Address, MemoryADT};
use deadpool_postgres::{CreatePoolError, Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use std::fmt;
use std::marker::PhantomData;
use tokio_postgres::{Config, NoTls, Socket, config::SslMode, tls::MakeTlsConnect};

#[derive(Debug)]
pub enum PostgresMemoryError {
    AsyncPostgresError(tokio_postgres::Error),
    TryFromSliceError(std::array::TryFromSliceError),
    CreatePoolError(deadpool_postgres::CreatePoolError),
    InvalidDataLength(usize),
}

impl std::error::Error for PostgresMemoryError {}

impl fmt::Display for PostgresMemoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AsyncPostgresError(err) => write!(f, "async-postgres error: {}", err),
            Self::TryFromSliceError(err) => write!(f, "try_from_slice error: {}", err),
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
    pool: Pool,
    _marker: PhantomData<(Address, Word)>,
}

const B_READ_STMT: &str = "
    SELECT f.w
    FROM UNNEST($1::bytea[]) WITH ORDINALITY AS params(addr, idx)
    LEFT JOIN findex_db f ON params.addr = f.a
    ORDER BY params.idx;
";

const G_WRITE_STMT: &str = "SELECT guarded_write($1, $2, $3, $4) as original_value";

impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize>
    PostGresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    pub async fn connect_with_pool<T>() -> Result<Self, PostgresMemoryError>
    where
        T: MakeTlsConnect<Socket>,
        T::Stream: Send + 'static, // 'static bound simply ensures that the type is fully owned
    {
        let mut pg_config = Config::new();
        pg_config
            .user("cosmian_findex")
            .password("cosmian_findex")
            .dbname("cosmian")
            .host("localhost")
            .application_name("findex_rust")
            .ssl_mode(SslMode::Prefer);
        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let mgr = Manager::from_config(pg_config, NoTls, mgr_config);
        let pool = Pool::builder(mgr)
            .max_size(16)
            .runtime(Runtime::Tokio1)
            .build()
            .unwrap();

        pool.get()
            .await
            .unwrap()
            .batch_execute(&format!(
                "
                    CREATE TABLE IF NOT EXISTS findex_db (
                        a BYTEA PRIMARY KEY CHECK (octet_length(a) = {}),
                        w BYTEA NOT NULL CHECK (octet_length(w) = {})
                    );
                    
                    CREATE OR REPLACE FUNCTION guarded_write(
                    guard_addr bytea, 
                    guard_value bytea, 
                    addresses bytea[], 
                    words bytea[]
                ) RETURNS bytea AS $$
                DECLARE
                    retry_count INT := 0;
                    max_retries INT := 10;
                    original_value bytea;
                    backoff_time INT;
                BEGIN
                
                    WITH guard_check AS (
                        SELECT w FROM findex_db WHERE a = guard_addr
                    ),
                    dedup_input_table AS (
                        SELECT DISTINCT ON (a) a, w
                        FROM UNNEST(addresses, words) WITH ORDINALITY AS t(a, w, order_idx)
                        ORDER BY a, order_idx DESC
                    ),
                    insert_cte AS (
                        INSERT INTO findex_db (a, w)
                        SELECT a, w FROM dedup_input_table AS t(a,w)
                        WHERE (
                            guard_value IS NULL AND NOT EXISTS (SELECT 1 FROM guard_check)
                        ) OR (
                            guard_value IS NOT NULL AND EXISTS (
                                SELECT 1 FROM guard_check WHERE w = guard_value
                            )
                        )
                        ON CONFLICT (a) DO UPDATE SET w = EXCLUDED.w
                    )
                    SELECT COALESCE((SELECT w FROM guard_check)) INTO original_value;
                              
                    
                    RETURN original_value;
                END;
                $$ LANGUAGE plpgsql PARALLEL SAFE;

                    ",
                ADDRESS_LENGTH, WORD_LENGTH
            ))
            .await?;

        Ok(Self {
            pool,
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
        let client = self.pool.get().await.unwrap(); // TODO: no unwrap in prod code
        let stmnt = client.prepare_cached(B_READ_STMT).await?;

        client
            // the left join is necessary to ensure that the order of the addresses is preserved
            // as well as to return None for addresses that don't exist
            .query(&stmnt, &[&addresses
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
        const MAX_RETRIES: usize = 10;
        let mut retry_count = 0;
        let mut last_error = None;

        while retry_count < MAX_RETRIES {
            // while counterintuitive, getting a new client on each retry is a better approach
            // than trying to reuse the same client since it allows other operations to use the
            // connection between retries, especially during backoff periods.
            let mut client = self.pool.get().await.unwrap();
            let stmnt = client.prepare_cached(G_WRITE_STMT).await?;
            if retry_count > 0 {
                let backoff =
                    std::time::Duration::from_millis(5 * 2u64.pow(retry_count as u32 - 1));
                tokio::time::sleep(backoff).await;
            }

            let result = async {
                // Start transaction with SERIALIZABLE isolation
                let tx = client
                    .build_transaction()
                    .isolation_level(tokio_postgres::IsolationLevel::Serializable)
                    .start()
                    .await?;

                let res = tx
                    .query_opt(&stmnt, &[
                        &*guard.0,
                        match &guard.1 {
                            Some(g) => g,
                            None => &None::<&[u8]>,
                        },
                        &addresses,
                        &words,
                    ])
                    .await?
                    .map_or(
                        Ok::<Option<[u8; WORD_LENGTH]>, PostgresMemoryError>(None),
                        |row| {
                            row.try_get::<_, Option<&[u8]>>(0)?
                                .map(|b| b.try_into())
                                .map_or(Ok(None), |r| Ok(Some(r?)))
                        },
                    );
                tx.commit().await?;
                Ok(res?)
            }
            .await;
            match result {
                Ok(value) => return Ok(value),
                Err(err) => {
                    // Check if it's a serialization failure (PostgreSQL error code 40001)
                    if let PostgresMemoryError::AsyncPostgresError(pg_err) = &err {
                        if let Some(code) = pg_err.code() {
                            if code.code() == "40001" {
                                // Serialization failure code
                                retry_count += 1;
                                last_error = Some(err);
                                continue;
                            }
                        }
                    }
                    // If it's not a serialization failure or we can't get the code, just return the error
                    return Err(err);
                }
            }
        }

        // If we've exhausted all retries, return the last error
        Err(last_error.unwrap())
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

    // const DB_URI: &str = "postgres://cosmian_findex:cosmian_findex@localhost/cosmian?application_name=findex_rust&sslmode=prefer";

    #[tokio::test]
    async fn test_rw_seq() -> Result<(), PostgresMemoryError> {
        // let (client, connection) = tokio_postgres::connect(DB_URI, NoTls).await?;
        let m = PostGresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect_with_pool::<
            NoTls,
        >()
        .await?;
        test_single_write_and_read::<WORD_LENGTH, _>(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), PostgresMemoryError> {
        let m = PostGresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect_with_pool::<
            NoTls,
        >()
        .await?;
        test_wrong_guard::<WORD_LENGTH, _>(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_collision_seq() -> Result<(), PostgresMemoryError> {
        let m = PostGresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect_with_pool::<
            NoTls,
        >()
        .await?;
        test_collisions::<WORD_LENGTH, _>(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), PostgresMemoryError> {
        let m = PostGresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect_with_pool::<
            NoTls,
        >()
        .await?;
        test_guarded_write_concurrent(&m, rand::random(), Some(100)).await;
        Ok(())
    }
}
