use super::PostgresMemoryError;
use crate::{Address, MemoryADT};
use deadpool_postgres::Pool;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct PostgresMemory<Address, Word> {
    pool: Pool,
    table_name: String,
    _marker: PhantomData<(Address, Word)>,
}

impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize>
    PostgresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    /// Returns a new memory instance from the given connection pool to a
    /// PostgreSQL database.
    pub async fn new_with_pool(pool: Pool, table_name: String) -> Self {
        Self {
            pool,
            table_name,
            _marker: PhantomData,
        }
    }

    /// Connects to a PostgreSQL database and creates a table if it doesn't
    /// exist.
    pub async fn initialize(&self) -> Result<(), PostgresMemoryError> {
        self.pool
            .get()
            .await?
            .execute(
                &format!(
                    "CREATE TABLE IF NOT EXISTS {} (
                        a BYTEA PRIMARY KEY CHECK (octet_length(a) = {}),
                        w BYTEA NOT NULL CHECK (octet_length(w) = {})
                    );",
                    self.table_name, ADDRESS_LENGTH, WORD_LENGTH
                ),
                &[],
            )
            .await?;

        Ok(())
    }

    /// Clears all bindings from this memory.
    #[cfg(feature = "test-utils")]
    pub async fn clear(&self) -> Result<(), PostgresMemoryError> {
        self.pool
            .get()
            .await?
            .execute(&format!("TRUNCATE TABLE {};", self.table_name), &[])
            .await?;

        Ok(())
    }

    fn gwrite_script(&self) -> String {
        format!(
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
        )
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

        // Statements are cached per connection and not per pool.
        let stmt = client
            .prepare_cached(&format!(
                // The left join is necessary to ensure that the order of the
                // addresses is preserved as well as to return None for addresses
                // that don't exist.
                "SELECT f.w
                        FROM UNNEST($1::bytea[]) WITH ORDINALITY AS params(addr, idx)
                        LEFT JOIN {} f ON params.addr = f.a
                        ORDER BY params.idx;",
                self.table_name
            ))
            .await?;

        client
            .query(
                &stmt,
                &[&addresses
                    .iter()
                    .map(|addr| addr.as_slice())
                    .collect::<Vec<_>>()],
            )
            .await?
            .iter()
            .map(|row| {
                row.try_get::<_, Option<&[u8]>>("w")?
                    .map(Self::Word::try_from)
                    .transpose()
                    .map_err(PostgresMemoryError::TryFromSliceError)
            })
            .collect()
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        let (addresses, words): (Vec<[u8; ADDRESS_LENGTH]>, Vec<Self::Word>) =
            bindings.into_iter().map(|(a, w)| (*a, w)).unzip();

        // Since a guarded write operation is lock-free, this loop is guaranteed
        // to terminate.
        loop {
            // Do not lock a resource for a potentially long loop, instead
            // request a new one at each iteration.
            let mut client = self.pool.get().await?;

            let stmt = client.prepare_cached(&self.gwrite_script()).await?;

            let res = async {
                let tx = client
                    .build_transaction()
                    .isolation_level(
                        deadpool_postgres::tokio_postgres::IsolationLevel::Serializable,
                    )
                    .start()
                    .await?;

                let res = tx
                    .query_opt(
                        &stmt,
                        &[
                            &*guard.0,
                            &guard.1.as_ref().map(|w| w.as_slice()),
                            &addresses,
                            &words,
                        ],
                    )
                    .await?
                    .map(|row| {
                        row.try_get::<_, Option<&[u8]>>(0)?
                            .map(Self::Word::try_from)
                            .transpose()
                            .map_err(PostgresMemoryError::TryFromSliceError)
                    })
                    .transpose()?
                    .flatten();

                tx.commit().await?;

                Ok(res)
            }
            .await;

            match res {
                Ok(value) => return Ok(value),
                Err(err) => {
                    // Retry on serialization failures (error code 40001),
                    // otherwise fail and return the error
                    if let PostgresMemoryError::TokioPostgresError(pg_err) = &err {
                        if pg_err.code().is_some_and(|code| code.code() == "40001") {
                            continue;
                        }
                    }
                    return Err(err);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ADDRESS_LENGTH,
        test_utils::{
            gen_seed, test_guarded_write_concurrent, test_rw_same_address,
            test_single_write_and_read, test_wrong_guard,
        },
    };

    use super::*;
    use cosmian_findex::WORD_LENGTH;
    use deadpool_postgres::Config;
    use tokio_postgres::NoTls;

    const DB_URL: &str = "postgres://cosmian:cosmian@localhost/cosmian";

    // Template function for pool creation
    pub async fn create_testing_pool(db_url: &str) -> Result<Pool, PostgresMemoryError> {
        let mut pg_config = Config::new();
        pg_config.url = Some(db_url.to_string());
        let pool = pg_config.builder(NoTls)?.build()?;
        Ok(pool)
    }

    // Setup function that handles pool creation, memory initialization, test
    // execution, and cleanup
    async fn setup_and_run_test<F, Fut>(
        table_name: &str,
        test_fn: F,
    ) -> Result<(), PostgresMemoryError>
    where
        F: FnOnce(PostgresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>) -> Fut + Send,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let test_pool = create_testing_pool(DB_URL).await.unwrap();
        let m = PostgresMemory::new_with_pool(test_pool.clone(), table_name.to_string()).await;

        m.initialize().await?;

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
        let m = PostgresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::new_with_pool(
            test_pool.clone(),
            table_name.to_string(),
        )
        .await;

        m.initialize().await?;

        // check that the table actually exists
        let client = test_pool.get().await?;
        let returned = client
            .query(
                &format!(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = '{}';",
                    table_name
                ),
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
            test_single_write_and_read(&m, gen_seed()).await;
        })
        .await
    }

    #[tokio::test]
    async fn test_guard_seq() -> Result<(), PostgresMemoryError> {
        setup_and_run_test("findex_test_guard_seq", |m| async move {
            test_wrong_guard(&m, gen_seed()).await;
        })
        .await
    }

    #[tokio::test]
    async fn test_rw_same_address_seq() -> Result<(), PostgresMemoryError> {
        setup_and_run_test("findex_test_rw_same_address_seq", |m| async move {
            test_rw_same_address(&m, gen_seed()).await;
        })
        .await
    }

    #[tokio::test]
    async fn test_rw_ccr() -> Result<(), PostgresMemoryError> {
        setup_and_run_test("findex_test_rw_ccr", |m| async move {
            test_guarded_write_concurrent(&m, gen_seed(), Some(100)).await;
        })
        .await
    }
}
