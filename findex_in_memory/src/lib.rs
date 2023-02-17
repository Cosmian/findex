#![allow(incomplete_features)]
#![feature(async_fn_in_trait)]

mod findex;

use std::fmt::Display;

pub use findex::FindexInMemory;

#[derive(Debug)]
pub struct Error(String);

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

impl cosmian_findex::CallbackError for Error {}
