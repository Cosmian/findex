use super::{BatchingMemoryADT, MemoryBatcher};
use cosmian_sse_memories::{Address, PostgresMemory};

impl<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize> BatchingMemoryADT
    for PostgresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>
{
    async fn batch_guarded_write(
        &self,
        write_operations: Vec<(
            (Self::Address, Option<Self::Word>),
            Vec<super::MemoryBinding<Self>>,
        )>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        // Since a guarded write operation is lock-free, this loop is guaranteed
        // to terminate given a fixed amount of concurrent queries.
        loop {
            // Do not lock a resource for a potentially long loop, instead
            // request a new one at each iteration.
            let mut client = self.get_pool().get().await?;

            let res = async {
                let tx = client
                    .build_transaction()
                    .isolation_level(
                        deadpool_postgres::tokio_postgres::IsolationLevel::Serializable,
                    )
                    .start()
                    .await?;

                let guarding_words = tx
                    .query(
                        &format!(
                            // The left join is necessary to ensure that the
                            // order of the addresses is preserved as well as to
                            // return None for addresses that don't exist.
                            "SELECT f.w
                             FROM UNNEST($1::bytea[]) WITH ORDINALITY AS params(addr, idx)
                             LEFT JOIN {} f
                             ON params.addr = f.a
                             ORDER BY params.idx;",
                            self.get_table_name()
                        ),
                        &[&write_operations
                            .iter()
                            .map(|((a, _), _)| a.as_slice())
                            .collect::<Vec<_>>()],
                    )
                    .await?
                    .iter()
                    .map(|row| {
                        row.try_get::<_, Option<&[u8]>>("w")?
                            .map(Self::Word::try_from)
                            .transpose()
                            .map_err(Self::Error::TryFromSliceError)
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let new_bindings = write_operations
                    .iter()
                    .zip(guarding_words.iter())
                    .filter_map(|(((_, w), bs), w_cur)| if w == w_cur { Some(bs) } else { None })
                    .flatten()
                    .map(|(a, w)| [a.as_slice(), w.as_slice()])
                    .flatten()
                    .collect::<Vec<_>>();

                tx.execute(
                    &format!(
                        "
                    INSERT INTO {0} (a, w)
                    VALUES {1}
                    ON CONFLICT (a) DO UPDATE SET w = EXCLUDED.w
                    ",
                        self.get_table_name(),
                        vec!["(?, ?)"; new_bindings.len()].join(",")
                    ),
                    &[&new_bindings],
                )
                .await?;

                tx.commit().await?;

                Ok(guarding_words)
            }
            .await;

            match res {
                Ok(value) => return Ok(value),
                Err(err) => {
                    // Retry on serialization failures (error code 40001),
                    // otherwise fail and return the error
                    if let Self::Error::TokioPostgresError(pg_err) = &err {
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

type PostgresMemoryBatcher<const ADDRESS_LENGTH: usize, const WORD_LENGTH: usize> =
    MemoryBatcher<PostgresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>>;

#[cfg(test)]
mod tests {
    use cosmian_sse_memories::MemoryADT;
    use deadpool_postgres::{Config, Pool, tokio_postgres::NoTls};

    use super::*;

    const ADDRESS_LENGTH: usize = 16;
    const WORD_LENGTH: usize = 16;

    const DB_URL: &str = "postgres://cosmian:cosmian@localhost/cosmian";

    type PgMemory = PostgresMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>;
    type PgMemoryError = <PgMemory as MemoryADT>::Error;

    // Template function for pool creation
    fn create_testing_pool(db_url: String) -> Result<Pool, PgMemoryError> {
        let mut pg_config = Config::new();
        pg_config.url = Some(db_url.to_string());
        let pool = pg_config.builder(NoTls)?.build()?;
        Ok(pool)
    }

    fn test_concurrent_batched_guarded_write() {
        let pool = create_testing_pool(DB_URL.to_string()).unwrap();
        let memory =
            PgMemory::new_with_pool(pool,
                                    "test_concurrent_batched_guarded_write".to_string());

        // let bindings
    }
}
