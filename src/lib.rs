#![warn(clippy::all, clippy::nursery, clippy::cargo)]

mod address;
mod adt;
mod byte_array;
#[cfg(any(test, feature = "bench"))]
mod encoding;
mod error;
mod findex;
mod memory;
mod ovec;
mod secret;
mod symmetric_key;
mod value;

pub use address::Address;
pub use adt::{IndexADT, MemoryADT};
pub use byte_array::ByteArray;
pub use error::Error;
pub use findex::{Findex, Op};
pub use memory::MemoryEncryptionLayer;
pub use secret::Secret;
pub use value::Value;

#[cfg(feature = "bench")]
pub use encoding::{WORD_LENGTH, Word, dummy_decode, dummy_encode};
#[cfg(any(test, feature = "bench"))]
pub use memory::InMemory;

/// 16-byte addresses ensure a high collision resistance that poses virtually no
/// limitation on the index.
pub const ADDRESS_LENGTH: usize = 16;

/// Using 32-byte cryptographic keys allows achieving post-quantum resistance
/// with the AES primitive.
pub const KEY_LENGTH: usize = 32;
