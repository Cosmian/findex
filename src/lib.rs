#![warn(clippy::all, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

mod address;
mod adt;
mod encoding;
mod error;
mod findex;
mod memory;
mod ovec;
mod secret;
mod symmetric_key;
mod value;

pub use address::Address;
#[cfg(any(test, feature = "test-utils"))]
pub use adt::test_utils;
pub use adt::{IndexADT, MemoryADT};
pub use encoding::{
    Decoder, Encoder,
    generic_encoding::{generic_decode, generic_encode},
};
#[cfg(any(test, feature = "test-utils"))]
pub use encoding::{
    dummy_encoding::{WORD_LENGTH, dummy_decode, dummy_encode},
    tests::test_encoding,
};
pub use error::Error;
pub use findex::{Findex, Op};
#[cfg(any(test, feature = "test-utils"))]
pub use memory::InMemory;
#[cfg(feature = "redis-mem")]
pub use memory::redis_store::{RedisMemory, RedisMemoryError};
#[cfg(feature = "sql-mem")]
pub use memory::sqlite_store::{SqlMemory, SqlMemoryError};
pub use secret::Secret;
pub use value::Value;

/// 16-byte addresses ensure a high collision resistance that poses virtually no
/// limitation on the index.
pub const ADDRESS_LENGTH: usize = 16;

/// Using 32-byte cryptographic keys allows achieving post-quantum resistance
/// with the AES primitive.
pub const KEY_LENGTH: usize = 32;
