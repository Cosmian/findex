//! This module implements the Findex interface for `SQlite`. It has been
//! written for testing purpose only.

use std::{
    collections::{HashMap, HashSet},
    usize,
};

use rusqlite::Connection;

use crate::{
    core::{FindexSearch, FindexUpsert, IndexedValue, KeyingMaterial, Keyword, Label, Location},
    error::FindexErr,
    interfaces::{
        generic_parameters::MASTER_KEY_LENGTH,
        sqlite::{database::SqliteDatabase, findex::RusqliteFindex, utils::get_db},
    },
};

mod database;
mod findex;
#[cfg(test)]
mod tests;
mod utils;

pub use utils::delete_db;

use super::generic_parameters::SECURE_FETCH_CHAINS_BATCH_SIZE;

pub async fn upsert(sqlite_path: &str, dataset_path: &str) -> Result<(), FindexErr> {
    //
    // Prepare database
    //
    let sqlite_db_path = get_db(sqlite_path);
    let mut connection = Connection::open(&sqlite_db_path)?;
    SqliteDatabase::new(&connection, dataset_path)?;

    //
    // Prepare data to index: we want to index all the user metadata found in
    // database. For each user, we create an unique database UID which will be
    // securely indexed with Findex.
    //
    let users = SqliteDatabase::select_all_users(&connection)?;
    let mut locations_and_words = HashMap::new();
    for (idx, user) in users.iter().enumerate() {
        let db_uid = (0..16)
            .into_iter()
            .map(|_e| format!("{:02x}", idx + 1))
            .collect::<String>();
        let mut words = HashSet::new();
        for word in &user.values() {
            words.insert(Keyword::from(word.as_bytes()));
        }
        locations_and_words.insert(
            IndexedValue::Location(Location::from(db_uid.as_bytes())),
            words,
        );
    }

    //
    // Create upsert instance
    //
    let mut rusqlite_upsert = RusqliteFindex {
        connection: &mut connection,
    };
    let label = Label::from(include_bytes!("../../../datasets/label").to_vec());
    let master_key_str = include_str!("../../../datasets/key.json");
    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::try_from(master_key_str)?;

    rusqlite_upsert
        .upsert(locations_and_words, &master_key, &label)
        .await?;

    connection
        .close()
        .map_err(|e| FindexErr::Other(format!("Error while closing connection: {e:?}")))
}

pub async fn search(
    sqlite_path: &str,
    bulk_words: HashSet<Keyword>,
    check: bool,
) -> Result<(), FindexErr> {
    let sqlite_db_path = get_db(sqlite_path);
    let mut connection = Connection::open(&sqlite_db_path)?;
    let mut rusqlite_search = RusqliteFindex {
        connection: &mut connection,
    };
    let master_key =
        KeyingMaterial::<MASTER_KEY_LENGTH>::try_from(include_str!("../../../datasets/key.json"))?;

    let label = Label::from(include_bytes!("../../../datasets/label").to_vec());
    let results = rusqlite_search
        .search(
            &bulk_words,
            &master_key,
            &label,
            10000,
            usize::MAX,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    let mut db_uids = Vec::with_capacity(results.len());
    for (_, indexed_values) in results {
        for iv in indexed_values {
            let db_uid = match iv {
                IndexedValue::Location(db_uid_location) => {
                    String::from_utf8(db_uid_location.into())
                        .map_err(|e| FindexErr::ConversionError(format!("Invalid location: {e}")))?
                }
                IndexedValue::NextKeyword(_) => {
                    return Err(FindexErr::Other(
                        "There should be not newt words".to_string(),
                    ));
                }
            };
            db_uids.push(db_uid);
        }
    }
    if check {
        db_uids.sort();
        let mut search_results: Vec<String> =
            serde_json::from_str(include_str!("../../../datasets/expected_db_uids.json"))?;
        search_results.sort();
        assert_eq!(db_uids, search_results);
    }
    Ok(())
}
