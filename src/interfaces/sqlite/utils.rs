use std::{collections::HashMap, path::PathBuf};

use cosmian_crypto_core::bytes_ser_de::Serializable;
use rusqlite::{Connection, Statement};

use crate::{
    core::{EncryptedTable, Uid},
    error::FindexErr,
    interfaces::{generic_parameters::UID_LENGTH, ser_de::deserialize_set},
};

#[derive(Debug)]
pub struct IndexEntry {
    pub uid: Vec<u8>,
    pub value: Vec<u8>,
}

pub fn prepare_questions(questions_number: usize) -> String {
    (0..questions_number)
        .into_iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",")
}

pub fn prepare_statement<'a>(
    connection: &'a Connection,
    serialized_uids: &[u8],
    table_name: &str,
) -> Result<Statement<'a>, FindexErr> {
    //
    // Deserialization of the input uids
    //
    let uids = deserialize_set::<Uid<UID_LENGTH>>(serialized_uids)?;

    //
    // Prepare statement
    //
    let lots_of_questions = prepare_questions(uids.len());
    let sql = format!("SELECT uid, value FROM {table_name} WHERE uid IN ({lots_of_questions})");
    let mut statement = connection.prepare(&sql)?;
    for (index, uid) in uids.iter().enumerate() {
        statement.raw_bind_parameter(index + 1, uid.to_vec())?;
    }
    Ok(statement)
}

pub fn sqlite_fetch_entry_table_items(
    connection: &Connection,
    serialized_entry_uids: &[u8],
) -> Result<Vec<u8>, FindexErr> {
    let mut stmt = prepare_statement(connection, serialized_entry_uids, "entry_table")?;

    let mut rows = stmt.raw_query();
    let mut entry_table_items = HashMap::new();
    while let Some(row) = rows.next()? {
        entry_table_items.insert(
            Uid::try_from_bytes(&row.get::<usize, Vec<u8>>(0)?)?,
            row.get(1)?,
        );
    }
    EncryptedTable::<UID_LENGTH>::from(entry_table_items).try_to_bytes()
}

pub fn get_db(sqlite_path: &str) -> PathBuf {
    let dir = std::env::temp_dir();
    dir.join(sqlite_path)
}

pub fn delete_db(sqlite_path: &str) -> Result<(), FindexErr> {
    let dir = std::env::temp_dir();
    let file_path = dir.join(sqlite_path);
    if file_path.exists() {
        std::fs::remove_file(file_path).map_err(FindexErr::IoError)?;
    }
    Ok(())
}
