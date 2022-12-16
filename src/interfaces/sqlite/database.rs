use faker_rand::{
    en_us::addresses::PostalCode,
    fr_fr::{
        addresses::Division,
        internet::Email,
        names::{FirstName, LastName},
        phones::PhoneNumber,
    },
};
use rusqlite::{Connection, Result};
use serde::{Deserialize, Serialize};

use crate::error::FindexErr;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize)]
pub struct User {
    pub(crate) firstName: String,
    pub(crate) lastName: String,
    pub(crate) phone: String,
    pub(crate) email: String,
    pub(crate) country: String,
    pub(crate) region: String,
    pub(crate) employeeNumber: String,
    pub(crate) security: String,
}
impl User {
    pub(crate) fn new() -> Self {
        Self {
            firstName: rand::random::<FirstName>().to_string(),
            lastName: rand::random::<LastName>().to_string(),
            phone: rand::random::<PhoneNumber>().to_string(),
            email: rand::random::<Email>().to_string(),
            country: "France".to_string(),
            region: rand::random::<Division>().to_string(),
            employeeNumber: rand::random::<PostalCode>().to_string(),
            security: "confidential".to_string(),
        }
    }

    pub(crate) fn values(&self) -> Vec<String> {
        vec![
            self.firstName.clone(),
            self.lastName.clone(),
            self.phone.clone(),
            self.email.clone(),
            self.country.clone(),
            self.region.clone(),
            self.employeeNumber.clone(),
            self.security.clone(),
        ]
    }
}

impl Default for User {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SqliteDatabase;

impl SqliteDatabase {
    pub(crate) fn new(connection: &Connection, dataset_path: &str) -> Result<Self, FindexErr> {
        Self::create_tables(connection)?;
        Self::insert_users(connection, dataset_path)?;
        Ok(Self {})
    }

    fn create_tables(conn: &Connection) -> Result<(), FindexErr> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id integer      PRIMARY KEY,
                firstName       text NOT NULL,
                lastName        text NOT NULL,
                email           text NOT NULL,
                phone           text NOT NULL,
                country         text NOT NULL,
                region          text NOT NULL,
                employeeNumber  text NOT NULL,
                security        text NOT NULL
              )",
            [], // empty list of parameters.
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS entry_table (
                  uid               BLOB PRIMARY KEY,
                  value             BLOB NOT NULL
              )",
            [], // empty list of parameters.
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS chain_table (
                  uid               BLOB PRIMARY KEY,
                  value             BLOB NOT NULL
                  )",
            [],
        )?;

        Ok(())
    }

    fn insert_users(conn: &Connection, dataset_path: &str) -> Result<(), FindexErr> {
        let dataset = std::fs::read_to_string(dataset_path)?;
        let users = serde_json::from_str::<Vec<User>>(&dataset)?;

        for user in &users {
            conn.execute(
                "INSERT INTO users (
            firstName,
            lastName,
            phone,
            email,
            country,
            region,
            employeeNumber,
            security
          )
          VALUES (
            :firstName,
            :lastName,
            :phone,
            :email,
            :country,
            :region,
            :employeeNumber,
            :security
          )",
                &[
                    (":firstName", &user.firstName),
                    (":lastName", &user.lastName),
                    (":phone", &user.phone),
                    (":email", &user.email),
                    (":country", &user.country),
                    (":region", &user.region),
                    (":employeeNumber", &user.employeeNumber),
                    (":security", &user.security),
                ],
            )?;
        }

        Ok(())
    }

    pub(crate) fn select_all_users(connection: &Connection) -> Result<Vec<User>, FindexErr> {
        let mut stmt = connection.prepare("SELECT * FROM users")?;
        let user_iter = stmt.query_map([], |row| {
            Ok(User {
                firstName: row.get("firstName")?,
                lastName: row.get("lastName")?,
                phone: row.get("email")?,
                email: row.get("phone")?,
                country: row.get("country")?,
                region: row.get("region")?,
                employeeNumber: row.get("employeeNumber")?,
                security: row.get("security")?,
            })
        })?;

        let users: Result<Vec<User>> = user_iter.collect();
        Ok(users?)
    }
}
