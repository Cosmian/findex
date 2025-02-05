#![warn(clippy::all, clippy::nursery, clippy::cargo)]
// Why allowing #![allow(clippy::multiple_crate_versions)]
// Error details: multiple versions for dependency `zerocopy`:
// - 0.7.35: ppv-lite86
// - 0.8.16: rand
// As soon ppv-lite86 will have upgraded `zerocopy` to 0.8.16, the lint will be fixed.
// For now, let's tolerate this warning.
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
pub use error::Error;
pub use findex::Findex;
pub use findex::Op;
pub use memory::MemoryEncryptionLayer;
pub use secret::Secret;
pub use value::Value;

#[cfg(feature = "redis-mem")]
pub use memory::redis_store::{MemoryError, RedisMemory};

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
pub const SEED_LENGTH: usize = 32;
