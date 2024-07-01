#![allow(clippy::type_complexity)]

mod address;
mod encoding;
mod error;
mod findex;
mod kv;
mod obf;
mod ovec;
mod stm;
mod value;

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    hash::Hash,
};

pub use address::Address;
pub use findex::Findex;
pub use kv::KvStore;
pub use stm::Stm;
pub use value::Value;

pub const ADDRESS_LENGTH: usize = 16;
pub const KEY_LENGTH: usize = 32;

/// An index stores *bindings*, that associate a keyword with a value. All values bound to the same
/// keyword are said to be *indexed under* this keyword. The number of such values is called the
/// volume of a keyword.
pub trait Index<'a, Keyword: Hash, Value: Hash> {
    type Error: std::error::Error;

    /// Search the index for the values bound to the given keywords.
    fn search(
        &'a self,
        keywords: impl Iterator<Item = Keyword>,
    ) -> impl Future<Output = Result<HashMap<Keyword, HashSet<Value>>, Self::Error>>;

    /// Add the given bindings to the index.
    fn insert(
        &'a self,
        bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    /// Remove the given bindings from the index.
    fn delete(
        &'a self,
        bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}
