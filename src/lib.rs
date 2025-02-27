#![warn(clippy::all, clippy::nursery, clippy::cargo)]

mod address;
mod adt;
mod encoding;
mod error;
mod findex;
mod memory;
mod ovec;
mod secret;
mod symmetric_key;

#[cfg(any(test, feature = "test-utils"))]
pub use adt::test_utils;
mod value;

pub use address::Address;
pub use adt::{IndexADT, MemoryADT};
pub use encoding::{
    Decoder, Encoder,
    generic_encoding::{generic_decode, generic_encode},
};
pub use error::Error;
pub use findex::Findex;
pub use findex::Op;
pub use secret::Secret;
pub use value::Value;

#[cfg(feature = "redis-mem")]
pub use memory::redis_store::{RedisMemory, RedisMemoryError};

#[cfg(feature = "sql-mem")]
pub use memory::sql_store::{SqlMemory, SqlMemoryError};

#[cfg(any(test, feature = "test-utils"))]
pub use encoding::{
    dummy_encoding::{WORD_LENGTH, dummy_decode, dummy_encode},
    tests::test_encoding,
};

#[cfg(any(test, feature = "test-utils"))]
pub use memory::InMemory;

/// 16-byte addresses ensure a high collision resistance that poses virtually no
/// limitation on the index.
pub const ADDRESS_LENGTH: usize = 16;

/// Using 32-byte cryptographic keys allows achieving post-quantum resistance
/// with the AES primitive.
pub const KEY_LENGTH: usize = 32;
