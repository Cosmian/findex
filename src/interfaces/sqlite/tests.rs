use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use super::{database::User, search, upsert, utils::delete_db};
use crate::{core::Keyword, error::FindexErr};

fn generate_new_dataset(nb_user: usize, dataset_filename: &str) {
    let mut users = Vec::new();
    for _i in 0..nb_user {
        let user = User::new();
        users.push(user);
    }
    // Save the JSON structure into the other file.
    std::fs::write(
        dataset_filename,
        serde_json::to_string_pretty(&users).unwrap(),
    )
    .unwrap();
}

#[actix_rt::test]
async fn test_findex_sqlite_no_regression() -> Result<(), FindexErr> {
    //
    // Prepare database and create Findex structs
    //
    let db = PathBuf::from("./datasets/sqlite.db");

    //
    // Search
    //
    search(
        &db,
        HashSet::from_iter([Keyword::from("France".as_bytes())]),
        true,
    )
    .await?;

    // Empty research (just in case)
    search(&db, HashSet::new(), false).await?;

    Ok(())
}

#[actix_rt::test]
async fn test_findex_sqlite_generate() -> Result<(), FindexErr> {
    //
    // Prepare database and create Findex structs
    //
    let file_path = Path::new("./target/sqlite.db");
    if file_path.exists() {
        std::fs::remove_file(file_path).map_err(FindexErr::IoError)?;
    }
    let db = PathBuf::from(file_path);

    //
    // Create new database
    //
    upsert(&db, "./datasets/data.json").await?;

    //
    // Search - simple check
    //
    search(
        &db,
        HashSet::from_iter([Keyword::from("France".as_bytes())]),
        true,
    )
    .await?;

    Ok(())
}

#[actix_rt::test]
async fn test_different_scenarios() -> Result<(), FindexErr> {
    delete_db("sqlite2.db")?;
    let db = std::env::temp_dir().join("sqlite2.db");
    for _ in 0..5 {
        //
        // Generate a new dataset and index it
        //
        generate_new_dataset(100, "french_dataset.json");
        upsert(&db, "./french_dataset.json").await?;

        //
        // Search
        //
        search(
            &db,
            HashSet::<Keyword>::from_iter([Keyword::from("France".as_bytes())]),
            false,
        )
        .await?;
    }

    delete_db("sqlite2.db")?;
    Ok(())
}
