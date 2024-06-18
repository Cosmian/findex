#![allow(clippy::type_complexity)]

mod address;
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

/// An index can insert and delete bindings, and search keywords.
pub trait Index<'a, Keyword: Hash, Value: Hash> {
    type Error: std::error::Error;

    fn search(
        &'a self,
        keywords: impl Iterator<Item = Keyword>,
    ) -> impl Future<Output = Result<HashMap<Keyword, HashSet<Value>>, Self::Error>>;

    fn insert(
        &'a self,
        bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    fn delete(
        bindings: impl Iterator<Item = (Keyword, HashSet<Value>)>,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}
