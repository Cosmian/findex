use std::sync::{Mutex, MutexGuard};
use postgres::{Client, NoTls}; //TODO change for tokio_postgres
use postgres::types::ToSql;
use itertools::Itertools;

use crate::MemoryADT;

pub struct PostGresMemory {
    table_name: String,
    connection: Mutex<Client>
}

impl PostGresMemory {
    fn new(db_path: &str, table_name: &str) -> Result<PostGresMemory, postgres::Error> {
        let connection = Client::connect(db_path, NoTls)?;

        let db = PostGresMemory {
            table_name: table_name.to_string(),
            connection: Mutex::new(connection)
        };

        Ok(db)
    }

    fn cnx(&self) -> MutexGuard<Client> {
        self.connection.lock().unwrap()
    }
}

impl MemoryADT
    for PostGresMemory
{
    type Address = Vec<u8>;
    type Word = Vec<u8>;
    type Error = postgres::Error;

    async fn batch_read(&self, a: Vec<Vec<u8>>) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        let addresses = a
            .iter()
            .map(|p| p as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();

        let m = format!(
            "({})",
            (1..=addresses.len())
                .format_with(",", |i, f| {
                    f(&format_args!("${i}"))
                }),
        );

        let mut db = self.cnx();

        let multi_rows = db.query(
            &format!(
                "SELECT * FROM {} WHERE addr IN {}",
                &self.table_name,
                &m
                ),
            &addresses)?;

        Ok(multi_rows.iter().map(|row| row.get("word")).collect())
    }

    async fn guarded_write(
        &self,
        guard: (Vec<u8>, Option<Vec<u8>>),
        bindings: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        let address_check_query = format!(
            "SELECT word FROM {} WHERE addr = $1",
            &self.table_name
        );

        let q = format!(
            "{}",
            (1..=bindings.len()*2)
                .tuples()
                .format_with(", ", |(i, j), f| {
                    f(&format_args!("(${i}, ${j})"))
                }),
        );

        let upsert_query = format!(
            "INSERT INTO {} (addr, word) VALUES {} ON CONFLICT (addr) DO UPDATE SET word = EXCLUDED.word",
            &self.table_name,
            &q
        );

        let (a, w_old) = guard;

        let bindings = bindings
            .iter()
            .flat_map(|(a, b)| vec![a, b])
            .map(|a| a as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();

        // Several questions (I'm not a PGSQL expert, these are real naive
        // questions):
        //
        // - isn't it possible to use one SQL command such as the one we
        //   discussed last time?
        //
        // - are you sure this is performed in one communication only?
        let mut db = self.cnx();
        let mut transaction = db.transaction()?;
        let rows = transaction.query(&address_check_query, &[&a])?;

        let cur: Option<Vec<u8>> = rows.get(0).map(|row| row.get("word"));

        if w_old == cur {
            let _rows = transaction.execute(&upsert_query, &bindings);
            let _ = transaction.commit()?;
            println!("Bindings written successfully");
        } else {
            let _ = transaction.rollback();
            println!("Guard binding did not match, no bindings written");
        }

        Ok(cur)
    }
}

#[cfg(test)]
mod tests {

    use crate::MemoryADT;
    use super::PostGresMemory;
    use futures::executor::block_on;

    /// Ensures a transaction can express a vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns the current value.
    #[test]
    fn test_vector_push() {
        let db_path = "postgresql://postgres:test@localhost/server_memory";
        let table_name = "enc_memory";

        let memory = PostGresMemory::new(db_path, table_name).unwrap();

        let table = memory.cnx().batch_execute(
            &format!(
            "DROP TABLE IF EXISTS {};
            CREATE TABLE {} (
                addr    BYTEA PRIMARY KEY,
                word    BYTEA
            )",
            &table_name,
            &table_name
            )
        );

        if table.is_err() {
            panic!("Cannot create table!");
        }

        assert_eq!(
            block_on(memory.guarded_write((vec![0], None), vec![(vec![0], vec![2]), (vec![1], vec![1]), (vec![2], vec![1])])).unwrap(),
            None
        );

        assert_eq!(
            block_on(memory.guarded_write((vec![0], None), vec![(vec![0], vec![4]), (vec![3], vec![2]), (vec![4], vec![2])])).unwrap(),
            Some(vec![2])
        );

        assert_eq!(
            block_on(memory.guarded_write((vec![0], Some(vec![2])), vec![(vec![0], vec![4]), (vec![3], vec![3]), (vec![4], vec![3])])).unwrap(),
            Some(vec![2])
        );

        assert_eq!(
            vec![Some(vec![1]), Some(vec![1]), Some(vec![3]), Some(vec![3])],
            block_on(memory.batch_read(vec![vec![1], vec![2], vec![3], vec![4]])).unwrap(),
        );
    }
}