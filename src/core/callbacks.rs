use std::collections::{HashMap, HashSet};

use crate::{
    core::{EncryptedTable, IndexedValue, Keyword, Location, Uid, UpsertData},
    error::FindexErr,
};

/// Trait implementing all callbacks needed by Findex.
pub trait FindexCallbacks<const UID_LENGTH: usize> {
    /// Returns partial results during a search. Stops the search if the
    /// returned value is `false`. This can be useful to stop the search when an
    /// intermediate result contains the search answers.
    ///
    /// - `results` : search results (graph leaves are ignored)
    async fn progress(
        &self,
        results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, FindexErr>;

    /// Fetch all the UIDs from the entry table
    async fn fetch_all_entry_table_uids(&self) -> Result<HashSet<Uid<UID_LENGTH>>, FindexErr>;

    /// Fetch the lines with the given UIDs from the Entry Table. The returned
    /// values are encrypted since they are stored that way. The decryption
    /// is performed by Findex.
    ///
    /// # Error
    ///
    /// No error is returned if an UID that does not exist in the Entry Table is
    /// requested since it can be the case when searching for a keyword that is
    /// not indexed.
    ///
    /// # Parameters
    ///
    /// - `entry_table_uids`    : UIDs of the lines to fetch from the Entry
    ///   Table
    async fn fetch_entry_table(
        &self,
        entry_table_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr>;

    /// Fetch the lines with the given UIDs from the Chain Table. The returned
    /// values are encrypted since they are stored that way. The decryption is
    /// performed by Findex.
    ///
    /// # Error
    ///
    /// No error is returned if an UID that does not exist in the Chain Table is
    /// requested since it can be the case during concurrent search and upsert
    /// operations.
    ///
    /// # Parameters
    ///
    /// - `chain_table_uids`    : UIDs of the lines to fetch from the Chain
    ///   Table
    async fn fetch_chain_table(
        &self,
        chain_table_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr>;

    /// Upserts lines in the Entry Table. The input data maps each Entry Table
    /// UID to upsert to the last value known by the client and the new value to
    /// upsert:
    ///
    /// `UID <-> (OLD_VALUE, NEW_VALUE)`
    ///
    /// To allow concurrent upsert operations:
    ///
    /// 1 - for each UID given, performs an *atomic* conditional upsert: if the
    /// current value stored in the DB is equal to `OLD_VALUE`, then `NEW_VALUE`
    /// is upserted;
    ///
    /// 2 - fetches the current values for all items that failed to be upserted
    /// in step 1 and returns them.
    ///
    /// # Parameters
    ///
    /// - `items`   : entries to be upserted
    async fn upsert_entry_table(
        &mut self,
        items: &UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexErr>;

    /// Inserts the given lines into the Entry Table.
    ///
    /// # Error
    ///
    /// This should return an error if a line with the same UID as one of the
    /// lines given already exists as this means that the index is corrupted.
    ///
    /// # Parameters
    ///
    /// - `items`   : items to be inserted
    async fn insert_entry_table(
        &mut self,
        items: &EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr>;

    /// Inserts the given lines into the Chain Table.
    ///
    /// # Error
    ///
    /// This should return an error if a line with the same UID as one of the
    /// lines given already exists as this means that the index is corrupted.
    ///
    /// # Parameters
    ///
    /// - `items`   : items to be inserted
    async fn insert_chain_table(
        &mut self,
        items: &EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexErr>;

    /// Removes entries from the Entry Table.
    ///
    /// # Error
    ///
    /// This should return an error if the line to removed is not found.
    ///
    /// # Parameters
    ///
    /// - `items`   : items to be removed
    async fn remove_entry_table(
        &mut self,
        items: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<(), FindexErr>;

    /// Removes entries from the Chain Table.
    ///
    /// # Error
    ///
    /// This should return an error if the line to removed is not found.
    ///
    /// # Parameters
    ///
    /// - `items`   : items to be removed
    async fn remove_chain_table(
        &mut self,
        items: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<(), FindexErr>;

    /// Returns all locations among the ones given that do not exist anymore.
    ///
    /// **NOTE**: this callback does not call the index database since indexed
    /// locations can be anything in Findex (DB UID, path, other ID...). It may
    /// not even call a database at all.
    ///
    /// # Parameters
    ///
    /// - `locations`   : locations queried
    fn list_removed_locations(
        &self,
        locations: &HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexErr>;
}
