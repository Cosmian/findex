#![warn(clippy::all, clippy::nursery, clippy::cargo)]
// This is necessary since CryptoCore depends on pkcs8 which depends on an old
// version of rand_core, which depends on an old version of getrandom (0.2.15),
// while CryptoCore also depends on gensym which depends on uuid, which depends
// on a newer version of getrandom (0.3.2).
#![allow(clippy::multiple_crate_versions)]

mod adt;
mod encoding;
mod encryption_layer;
mod error;
mod findex;
mod ovec;

#[cfg(feature = "test-utils")]
mod benches;
#[cfg(feature = "test-utils")]
pub use benches::*;

pub use adt::IndexADT;
pub use encoding::{
    Decoder, Encoder,
    generic_encoding::{generic_decode, generic_encode},
};
pub use encryption_layer::{KEY_LENGTH, MemoryEncryptionLayer};
pub use error::Error;
pub use findex::Findex;
pub use findex::Op;

#[cfg(any(test, feature = "test-utils"))]
pub use encoding::{
    dummy_encoding::{WORD_LENGTH, dummy_decode, dummy_encode},
    tests::test_encoding,
};

#[cfg(any(test, feature = "test-utils"))]
pub mod reexport {
    // Re-exporting the most commonly used runtime interfaces for convenience.
    pub use agnostic_lite::{smol, tokio, wasm};
}