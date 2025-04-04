use super::PostgresMemoryError;
use crate::{Address, MemoryADT};
use deadpool_postgres::Pool;
use std::marker::PhantomData;
use tokio_postgres::{
    Socket,
    tls::{MakeTlsConnect, TlsConnect},
};

#[derive(Clone, Debug)]
pub struct PostgresMemory<Address, Word> {
    pool: Pool,
    table_name: String,
    _marker: PhantomData<(Address, Word)>,
}

impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize>
    PostgresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    /// Connect to a Postgres database and create a table if it doesn't exist
    pub async fn initialize_table<T>(
        &self,
        db_url: String,
        table_name: String,
        tls: T,
    ) -> Result<(), PostgresMemoryError>
    where
        T: MakeTlsConnect<Socket> + Send,
        T::Stream: Send + 'static,
        T::TlsConnect: Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let (client, connection) = tokio_postgres::connect(&db_url, tls).await?;

        // The connection object performs the actual communication with the database
        // `Connection` only resolves when the connection is closed, either because a fatal error has
        // occurred, or because its associated `Client` has dropped and all outstanding work has completed.
        let conn_handle = tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });

        let returned = client
            .execute(
                &format!(
                    "
                    CREATE TABLE IF NOT EXISTS {} (
                        a BYTEA PRIMARY KEY CHECK (octet_length(a) = {}),
                        w BYTEA NOT NULL CHECK (octet_length(w) = {})
                    );",
                    table_name, ADDRESS_LENGTH, WORD_LENGTH
                ),
                &[],
            )
            .await?;
        if returned != 0 {
            return Err(PostgresMemoryError::TableCreationError(returned));
        }

        drop(client);
        let _ = conn_handle.await; // ensures that the connection is closed
        Ok(())
    }

    /// Connect to a Postgres database and create a table if it doesn't exist
    pub async fn connect_with_pool(
        pool: Pool,
        table_name: String,
    ) -> Result<Self, PostgresMemoryError> {
        Ok(Self {
            pool,
            table_name,
            _marker: PhantomData,
        })
    }
}

impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize> MemoryADT
    for PostgresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    type Address = Address<ADDRESS_LENGTH>;
    type Word = [u8; WORD_LENGTH];
    type Error = PostgresMemoryError;

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        let client = self.pool.get().await?;
        // in psql, statements are cached per connection and not per pool
        let stmt = client
            .prepare_cached(
                format!(
                    "SELECT f.w
                        FROM UNNEST($1::bytea[]) WITH ORDINALITY AS params(addr, idx)
                        LEFT JOIN {} f ON params.addr = f.a
                        ORDER BY params.idx;",
                    self.table_name
                )
                .as_str(),
            )
            .await?;

        client
            // the left join is necessary to ensure that the order of the addresses is preserved
            // as well as to return None for addresses that don't exist
            .query(&stmt, &[&addresses
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
            .collect()
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let g_write_script = format!(
            "
        WITH
        guard_check AS (
            SELECT w FROM {0} WHERE a = $1::bytea
        ),
        dedup_input_table AS (
        SELECT DISTINCT ON (a) a, w
            FROM UNNEST($3::bytea[], $4::bytea[]) WITH ORDINALITY AS t(a, w, order_idx)
            ORDER BY a, order_idx DESC
        ),
        insert_cte AS (
            INSERT INTO {0} (a, w)
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
            self.table_name
        );

        let (addresses, words): (Vec<[u8; ADDRESS_LENGTH]>, Vec<Self::Word>) =
            bindings.into_iter().map(|(a, w)| (*a, w)).unzip();
        const MAX_RETRIES: usize = 10;

        for _ in 0..MAX_RETRIES {
            // while counterintuitive, getting a new client on each retry is a better approach
            // than trying to reuse the same client since it allows other operations to use the
            // connection between retries.
            let mut client = self.pool.get().await?;
            let stmt = client.prepare_cached(g_write_script.as_str()).await?;

            let result = async {
                let tx = client
                    .build_transaction()
                    .isolation_level(
                        deadpool_postgres::tokio_postgres::IsolationLevel::Serializable,
                    )
                    .start()
                    .await?;

                let res = tx
                    .query_opt(&stmt, &[
                        &*guard.0,
                        &guard.1.as_ref().map(|w| w.as_slice()),
                        &addresses,
                        &words,
                    ])
                    .await?
                    .map_or(
                        Ok::<Option<[u8; WORD_LENGTH]>, PostgresMemoryError>(None),
                        |row| {
                            row.try_get::<_, Option<&[u8]>>(0)?
                                .map_or(Ok(None), |r| Ok(Some(r.try_into()?)))
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
    use deadpool_postgres::Config;
    use tokio_postgres::NoTls;

    use super::*;
    use crate::{
        ADDRESS_LENGTH, Address, WORD_LENGTH,
        adt::test_utils::{
            test_guarded_write_concurrent, test_rw_same_address, test_single_write_and_read,
            test_wrong_guard,
        },
    };

    const DB_URL: &str = "postgres://cosmian:cosmian@localhost/cosmian";

    // Template function for pool creation
    pub async fn create_testing_pool(db_url: &str) -> Result<Pool, PostgresMemoryError> {
        let mut pg_config = Config::new();
        pg_config.url = Some(db_url.to_string());
        let pool = pg_config.builder(NoTls)?.build()?;
        Ok(pool)
    }

    // Setup function that handles pool creation, memory initialization, test execution, and cleanup
    async fn setup_and_run_test<F, Fut>(
        table_name: &str,
        test_fn: F,
    ) -> Result<(), PostgresMemoryError>
    where
        F: FnOnce(PostgresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>) -> Fut + Send,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let test_pool = create_testing_pool(DB_URL).await.unwrap();
        let m = PostgresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect_with_pool(
            test_pool.clone(),
            table_name.to_string(),
        )
        .await?;

        m.initialize_table(DB_URL.to_string(), table_name.to_string(), NoTls)
            .await?;

        test_fn(m).await;

        // Cleanup - drop the table to avoid flacky tests
        test_pool
            .get()
            .await?
            .execute(&format!("DROP table {};", table_name), &[])
            .await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_initialization() -> Result<(), PostgresMemoryError> {
        let table_name: &str = "test_initialization";
        let test_pool = create_testing_pool(DB_URL).await.unwrap();
        let m = PostgresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect_with_pool(
            test_pool.clone(),
            table_name.to_string(),
        )
        .await?;

        m.initialize_table(DB_URL.to_string(), table_name.to_string(), NoTls)
            .await?;

        // check that the table actually exists
        let client = test_pool.get().await?;
        let returned = client
            .query(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'test_initialization';",
                &[],
            )
            .await?;

        assert_eq!(returned[0].get::<_, i64>(0), 1);

        // Cleanup - drop the table to avoid flacky tests
        test_pool
            .get()
            .await?
            .execute(&format!("DROP table {table_name};"), &[])
            .await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_rw_seq() -> Result<(), PostgresMemoryError> {
        setup_and_run_test("findex_test_rw_seq", |m| async move {
            test_single_write_and_read::<WORD_LENGTH, _>(&m, rand::random()).await;
        })
        .await
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), PostgresMemoryError> {
        setup_and_run_test("findex_test_guard_seq", |m| async move {
            test_wrong_guard::<WORD_LENGTH, _>(&m, rand::random()).await;
        })
        .await
    }

    #[tokio::test]
    async fn test_rw_same_address_seq() -> Result<(), PostgresMemoryError> {
        setup_and_run_test("findex_test_rw_same_address_seq", |m| async move {
            test_rw_same_address::<WORD_LENGTH, _>(&m, rand::random()).await;
        })
        .await
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), PostgresMemoryError> {
        setup_and_run_test("findex_test_rw_ccr", |m| async move {
            test_guarded_write_concurrent::<WORD_LENGTH, _>(&m, rand::random(), Some(100)).await;
        })
        .await
    }
}
