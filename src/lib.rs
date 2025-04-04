#![warn(clippy::all, clippy::nursery, clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

mod address;
mod adt;
mod encoding;
mod error;
mod findex;
mod memory;
mod ovec;
#[cfg(any(test, feature = "test-utils"))]
mod test_utils;

pub use address::Address;
pub use adt::{IndexADT, MemoryADT};
pub use encoding::{
    Decoder, Encoder,
    generic_encoding::{generic_decode, generic_encode},
};
pub use error::Error;
pub use findex::Findex;
pub use findex::Op;
pub use memory::MemoryEncryptionLayer;

#[cfg(any(test, feature = "test-utils"))]
pub use test_utils::*;

#[cfg(feature = "redis-mem")]
pub use memory::{RedisMemory, RedisMemoryError};

#[cfg(feature = "sqlite-mem")]
pub use memory::{SqliteMemory, SqliteMemoryError};

#[cfg(feature = "postgres-mem")]
pub use memory::{PostgresMemory, PostgresMemoryError};

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
