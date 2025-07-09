#![warn(clippy::all, clippy::nursery, clippy::cargo)]
// This is necessary since CryptoCore depends on pkcs8 which depends on an old
// version of rand_core, which depends on an old version of getrandom (0.2.15),
// while CryptoCore also depends on gensym which depends on uuid, which depends
// on a newer version of getrandom (0.3.2).
#![allow(clippy::multiple_crate_versions)]

mod adt;
mod encoding;
mod error;
mod findex;
mod memory;
mod ovec;

#[cfg(any(test, feature = "test-utils"))]
mod test_utils;

pub use adt::IndexADT;
pub use encoding::{
    Decoder, Encoder,
    generic_encoding::{generic_decode, generic_encode},
};
pub use error::Error;
pub use findex::Findex;
pub use findex::Op;
pub use memory::{KEY_LENGTH, MemoryEncryptionLayer};

#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::*;

#[cfg(any(test, feature = "test-utils"))]
pub use encoding::{
    dummy_encoding::{WORD_LENGTH, dummy_decode, dummy_encode},
    tests::test_encoding,
};
