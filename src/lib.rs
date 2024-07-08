#![allow(clippy::type_complexity)]

mod address;
mod adt;
mod encoding;
mod encryption_layer;
mod error;
mod findex;
mod ovec;
mod value;

pub use address::Address;
pub use adt::{IndexADT, MemoryADT};
pub use findex::Findex;
pub use value::Value;

#[cfg(any(test, feature = "bench"))]
mod kv;
#[cfg(feature = "bench")]
pub use encoding::{dummy_decode, dummy_encode, Op};
#[cfg(feature = "bench")]
pub use kv::KvStore;

/// 16-byte addresses ensure a high collision resistance that poses virtually no limitation on the
/// index.
///
/// 8-byte addresses can also be used for smaller indexes if storage is the limiting factor, in
/// which case the number of addresses in used at which collisions are to be expected is
/// approximately 2^32 (see the birthday paradox for more details). Keyword collision can be
/// mitigated by marking n bit of the addresses, allowing to statistically store up to 2^((64-n)/2)
/// keywords, and reducing the number of words that can be used to store associated values to
/// sqrt(2^64 - 2^n).
pub const ADDRESS_LENGTH: usize = 16;

/// Using 32-byte cryptographic keys allow achieving post-quantum resistance if the adequate
/// primitives are used (e.g. AES).
pub const KEY_LENGTH: usize = 32;
