use std::collections::{HashMap, HashSet};

use crate::edx::EncryptedValue;

/// Queries the Entry Table for the given tokens (UIDs).
///
/// The tokens that do not index any value in the Entry Table should not be
/// present in the returned map.
///
/// # Error
///
/// No error should be returned in case a requested token does not index any
/// value.
pub type FetchEntry<const TOKEN_LENGTH: usize, const VALUE_LENGTH: usize, Error> =
    fn(
        tokens: HashSet<[u8; TOKEN_LENGTH]>,
    ) -> Result<HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>, Error>;

/// Upserts the given values into the Entry Table.
///
/// The upsert operation on each token should be *atomic* and *conditional*:
/// - if there is no value in both the set of old values and the encrypted
///   dictionary, inserts the new value;
/// - if there is a value in the set of old values that matches the value in the
///   encrypted dictionary, replaces it by the new value;
/// - if there is a value in the set of old values that does not match the value
///   in the encrypted dictionary, returns the encrypted value stored;
/// - if there is a value in the set of old values but no value in the encrypted
///   dictionary, returns an error.
pub type UpsertEntry<const TOKEN_LENGTH: usize, const VALUE_LENGTH: usize, Error> =
    fn(
        old_values: &HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>,
        new_values: &HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>,
    ) -> Result<HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>, Error>;

/// Queries the Chain Table for the given tokens (UIDs).
///
/// The tokens that do not index any value in the Chain Table should not be
/// present in the returned map.
///
/// # Error
///
/// No error should be returned in case a requested token does not index any
/// value.
pub type FetchChain<const TOKEN_LENGTH: usize, const VALUE_LENGTH: usize, Error> =
    fn(
        tokens: HashSet<[u8; TOKEN_LENGTH]>,
    ) -> Result<HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>, Error>;

pub type InsertChain<const TOKEN_LENGTH: usize, const VALUE_LENGTH: usize, Error> =
    fn(
        tokens: HashMap<[u8; TOKEN_LENGTH], EncryptedValue<VALUE_LENGTH>>,
    ) -> Result<HashSet<[u8; TOKEN_LENGTH]>, Error>;
