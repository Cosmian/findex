use std::collections::{HashMap, HashSet};

use crate::{chain_table, entry_table};

pub type FetchEntry<const TOKEN_LENGTH: usize, const VALUE_LENGTH: usize, Error> =
    fn(
        tokens: HashSet<[u8; TOKEN_LENGTH]>,
    )
        -> Result<HashMap<[u8; TOKEN_LENGTH], entry_table::EncryptedValue<VALUE_LENGTH>>, Error>;

pub type UpsertEntry<const TOKEN_LENGTH: usize, const VALUE_LENGTH: usize, Error> =
    fn(
        old_values: &HashMap<[u8; TOKEN_LENGTH], entry_table::EncryptedValue<VALUE_LENGTH>>,
        new_values: &HashMap<[u8; TOKEN_LENGTH], entry_table::EncryptedValue<VALUE_LENGTH>>,
    )
        -> Result<HashMap<[u8; TOKEN_LENGTH], entry_table::EncryptedValue<VALUE_LENGTH>>, Error>;

pub type FetchChain<const TOKEN_LENGTH: usize, const VALUE_LENGTH: usize, Error> =
    fn(
        tokens: HashSet<[u8; TOKEN_LENGTH]>,
    )
        -> Result<HashMap<[u8; TOKEN_LENGTH], chain_table::EncryptedValue<VALUE_LENGTH>>, Error>;
