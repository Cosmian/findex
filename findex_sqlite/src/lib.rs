//! This crate implements the Findex interface for `SQlite`. It has been

#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use base64::{engine::general_purpose, Engine};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_findex::{
    parameters::{MASTER_KEY_LENGTH, SECURE_FETCH_CHAINS_BATCH_SIZE},
    FindexSearch, FindexUpsert, IndexedValue, KeyingMaterial, Keyword, Label, Location,
};
use database::SqliteDatabase;
use findex::RusqliteFindex;
use rusqlite::Connection;

mod database;
mod error;
mod findex;
mod ser_de;
pub mod utils;

pub use database::User;
pub use error::Error;

pub async fn upsert(sqlite_db_path: &PathBuf, dataset_path: &str) -> Result<(), Error> {
    //
    // Prepare database
    //
    let mut connection = Connection::open(sqlite_db_path)?;
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
    let label = Label::from(include_bytes!("../../datasets/label").to_vec());
    let master_key_bytes = general_purpose::STANDARD
        .decode(include_str!("../../datasets/key.json"))
        .map_err(|e| Error::Other(e.to_string()))?;
    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(&master_key_bytes)?;

    rusqlite_upsert
        .upsert(locations_and_words, &master_key, &label)
        .await?;

    connection.close().map_err(|(_, e)| Error::RusqliteError(e))
}

pub async fn search(
    sqlite_path: &PathBuf,
    bulk_words: HashSet<Keyword>,
    check: bool,
) -> Result<(), Error> {
    let mut connection = Connection::open(sqlite_path)?;
    let mut rusqlite_search = RusqliteFindex {
        connection: &mut connection,
    };
    let master_key_bytes = general_purpose::STANDARD
        .decode(include_str!("../../datasets/key.json"))
        .map_err(|e| Error::Other(e.to_string()))?;
    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::try_from_bytes(&master_key_bytes)?;

    let label = Label::from(include_bytes!("../../datasets/label").to_vec());
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
    for (_, locations) in results {
        for location in locations {
            let db_uid = String::from_utf8(location.into())
                .map_err(|e| Error::Other(format!("Invalid location: {e}")))?;
            db_uids.push(db_uid);
        }
    }
    if check {
        db_uids.sort();
        let mut search_results: Vec<String> =
            serde_json::from_str(include_str!("../../datasets/expected_db_uids.json"))?;
        search_results.sort();
        assert_eq!(db_uids, search_results);
    }
    Ok(())
}
