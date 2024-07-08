use crate::{DbInterfaceErrorTrait, Set};

#[cfg(feature = "in_memory")]
pub mod in_memory_db;
mod structs;

pub use structs::{Edx, Token};

pub trait EdxDbInterface {
    /// Type of error returned by the EDX.
    type Error: DbInterfaceErrorTrait;

    /// Queries an EDX for the given tokens. Only returns a value for the tokens
    /// that are present in the store.
    async fn fetch(&self, tokens: Set<Token>) -> Result<Edx, Self::Error>;

    /// Upserts the given values into the database for the given tokens.
    ///
    /// For each new token:
    /// 1. if there is no old value and no value stored, inserts the new value;
    /// 2. if there is an old value but no value stored, returns an error;
    /// 3. if the old value is equal to the value stored, updates the value stored
    ///    with the new value;
    /// 4. else returns the value stored with its associated token.
    ///
    /// A summary of the different cases is presented in the following table:
    ///
    /// +--------------+----------+-----------+-----------+
    /// | stored \ old | None     | Some("A") | Some("B") |
    /// +--------------+----------+-----------+-----------+
    /// | None         | upserted | *error*   | *error*   |
    /// | Some("A")    | rejected | upserted  | rejected  |
    /// | Some("B")    | rejected | rejected  | upserted  |
    /// +--------------+----------+-----------+-----------+
    ///
    /// All modifications of the EDX should be *atomic*.
    async fn upsert(&self, old_values: Edx, new_values: Edx) -> Result<Edx, Self::Error>;

    /// Inserts the given values into the Edx for the given tokens.
    ///
    /// # Error
    ///
    /// If a value is already stored for one of these tokens, no new value
    /// should be inserted and an error should be returned.
    async fn insert(&self, values: Edx) -> Result<Edx, Self::Error>;

    /// Deletes the lines associated to the given tokens from the EDX.
    async fn delete(&self, tokens: Set<Token>) -> Result<(), Self::Error>;

    /// Returns all data stored through this interface.
    async fn dump(&self) -> Result<Edx, Self::Error>;
}
