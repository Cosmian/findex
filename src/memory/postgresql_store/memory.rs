use super::PostgresMemoryError;
use crate::{Address, MemoryADT};
use deadpool_postgres::Pool;
use std::marker::PhantomData;
use tokio_postgres::{Socket, tls::MakeTlsConnect};

#[derive(Clone, Debug)]
pub struct PostGresMemory<Address, Word> {
    pool: Pool,
    _marker: PhantomData<(Address, Word)>,
}

impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize>
    PostGresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    pub async fn connect_with_pool<T>(pool: Pool) -> Result<Self, PostgresMemoryError>
    where
        T: MakeTlsConnect<Socket>,
        T::Stream: Send + 'static, // 'static bound simply ensures that the type is fully owned
    {
        pool.get()
            .await?
            .execute(
                &format!(
                    "
                    CREATE TABLE IF NOT EXISTS findex_db (
                        a BYTEA PRIMARY KEY CHECK (octet_length(a) = {}),
                        w BYTEA NOT NULL CHECK (octet_length(w) = {})
                    );
                    ",
                    ADDRESS_LENGTH, WORD_LENGTH
                ),
                &[],
            )
            .await?;

        Ok(Self {
            pool,
            _marker: PhantomData,
        })
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
        let client = self.pool.get().await?;
        // statements are cached per connection and not per pool
        let stmnt = client
            .prepare_cached(
                "SELECT f.w
                        FROM UNNEST($1::bytea[]) WITH ORDINALITY AS params(addr, idx)
                        LEFT JOIN findex_db f ON params.addr = f.a
                        ORDER BY params.idx;",
            )
            .await?;

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
        if bindings.is_empty() {
            // When PostgreSQL encounters a VALUES clause with nothing inside it it will throw a syntax error.
            return self
                .batch_read(vec![guard.0])
                .await
                .map(|v| v.into_iter().next().flatten());
        }

        let (addresses, words): (Vec<[u8; ADDRESS_LENGTH]>, Vec<Self::Word>) =
            bindings.into_iter().map(|(a, w)| (*a, w)).unzip();
        const MAX_RETRIES: usize = 10;

        for _ in 0..MAX_RETRIES {
            // while counterintuitive, getting a new client on each retry is a better approach
            // than trying to reuse the same client since it allows other operations to use the
            // connection between retries.
            let mut client = self.pool.get().await?;
            let stmnt = client
                .prepare_cached(
                    " WITH
                            guard_check AS (
                                SELECT w FROM findex_db WHERE a = $1::bytea
                            ),
                            dedup_input_table AS (
                            SELECT DISTINCT ON (a) a, w
                                FROM UNNEST($3::bytea[], $4::bytea[]) WITH ORDINALITY AS t(a, w, order_idx)
                                ORDER BY a, order_idx DESC
                            ),
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
                            SELECT COALESCE((SELECT w FROM guard_check)) AS original_guard_value;",
                )
                .await?;

            // INFO: a backoff mechanism can be added here to handle high contention use cases

            let result = async {
                // Start transaction with SERIALIZABLE isolation
                let tx = client
                    .build_transaction()
                    .isolation_level(tokio_postgres::IsolationLevel::Serializable)
                    .start() // BEGIN PG statement equivalent
                    .await?;

                let res = tx
                    .query_opt(&stmnt, &[
                        &*guard.0,
                        guard.1.as_ref().map_or(&None::<&[u8]>, |g| g),
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
                    )?;
                tx.commit().await?;
                Ok(res)
            }
            .await;
            match result {
                Ok(value) => return Ok(value),
                Err(err) => {
                    // Retry on serialization failures (error code 40001), otherwise fail and return the error
                    if let PostgresMemoryError::TokioPostgresError(pg_err) = &err {
                        if pg_err.code().is_some_and(|code| code.code() == "40001") {
                            continue;
                        }
                    }
                    return Err(err);
                }
            }
        }
        Err(PostgresMemoryError::RetryExhaustedError(MAX_RETRIES))
    }
}

#[cfg(test)]
mod tests {
    use deadpool_postgres::{Manager, ManagerConfig, RecyclingMethod, Runtime};
    use tokio_postgres::{Config, NoTls, config::SslMode};

    use super::*;
    use crate::{
        ADDRESS_LENGTH, Address, WORD_LENGTH,
        adt::test_utils::{
            test_guarded_write_concurrent, test_rw_same_address, test_single_write_and_read,
            test_wrong_guard,
        },
    };

    // Template function to create for pool creation
    pub async fn create_testing_pool<T>() -> Result<Pool, PostgresMemoryError>
    where
        T: MakeTlsConnect<Socket>,
        T::Stream: Send + 'static,
    {
        let mut pg_config = Config::new();
        pg_config
            .user("cosmian_findex")
            .password("cosmian_findex") // in production code, use a secure way to store the password
            .dbname("cosmian")
            .host("localhost")
            .application_name("findex_rust")
            .ssl_mode(SslMode::Prefer);

        let mgr = Manager::from_config(pg_config, NoTls, ManagerConfig {
            // In most cases, the default fast recycling method is appropriate
            recycling_method: RecyclingMethod::Fast,
        });

        let pool = Pool::builder(mgr)
            // a bigger pool size might be more appropriate, tune according to your needs and the available resources
            // the command `SHOW max_connections;` in psql will give you the maximum number of connections, which is 100 by default
            .max_size(16)
            .runtime(Runtime::Tokio1)
            .build()?;

        Ok(pool)
    }

    #[tokio::test]
    async fn test_rw_seq() -> Result<(), PostgresMemoryError> {
        // let (client, connection) = tokio_postgres::connect(DB_URI, NoTls).await?;
        let m = PostGresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect_with_pool::<
            NoTls,
        >(create_testing_pool::<NoTls>().await.unwrap())
        .await?;
        test_single_write_and_read::<WORD_LENGTH, _>(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), PostgresMemoryError> {
        let m = PostGresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect_with_pool::<
            NoTls,
        >(create_testing_pool::<NoTls>().await.unwrap())
        .await?;
        test_wrong_guard::<WORD_LENGTH, _>(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_rw_same_address_seq() -> Result<(), PostgresMemoryError> {
        let m = PostGresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect_with_pool::<
            NoTls,
        >(create_testing_pool::<NoTls>().await.unwrap())
        .await?;
        test_rw_same_address::<WORD_LENGTH, _>(&m, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), PostgresMemoryError> {
        let m = PostGresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect_with_pool::<
            NoTls,
        >(create_testing_pool::<NoTls>().await.unwrap())
        .await?;
        test_guarded_write_concurrent(&m, rand::random(), Some(20)).await;
        Ok(())
    }
}
