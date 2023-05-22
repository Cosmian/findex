// used in `errors.rs`
#![feature(never_type)]
// used in `edx.rs` and `emm.rs`
#![feature(associated_type_defaults)]
#![allow(unused_variables)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(inherent_associated_types)]
#![allow(dead_code)]

#[macro_use]
mod macros;

mod chain_table;
mod edx;
mod emm;
mod entry_table;
mod error;
mod findex;
mod parameters;

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;
use error::Error;
use zeroize::ZeroizeOnDrop;

pub trait FindexApi<
    Tag: Hash + PartialEq + Eq,
    Data: Hash + PartialEq + Eq,
    CallbackError: std::error::Error,
>
{
    type Seed: ZeroizeOnDrop;
    type Key: ZeroizeOnDrop;

    fn gen_seed(&self, rng: &mut impl CryptoRngCore) -> Self::Seed;

    fn tokenize(&self, seed: &Self::Seed) -> Self::Key;

    fn search(&self, key: &Self::Key, tags: HashSet<Tag>) -> HashMap<Tag, HashSet<Data>>;

    fn add(
        &mut self,
        key: &Self::Key,
        items: HashMap<Tag, HashSet<Data>>,
    ) -> Result<(), Error<CallbackError>>;

    fn delete(
        &mut self,
        key: &Self::Key,
        items: HashMap<Tag, HashSet<Data>>,
    ) -> Result<(), Error<CallbackError>>;
}
