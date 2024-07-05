#![allow(clippy::type_complexity)]

mod address;
mod adt;
mod el;
mod encoding;
mod error;
mod findex;
mod kv;
mod ovec;
mod value;

pub use address::Address;
pub use adt::{IndexADT, MemoryADT};
pub use findex::Findex;
pub use kv::KvStore;
pub use value::Value;

#[cfg(feature = "bench")]
pub use encoding::{dummy_decode, dummy_encode, Op};

pub const ADDRESS_LENGTH: usize = 16;
pub const KEY_LENGTH: usize = 32;
