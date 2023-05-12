// used in `errors.rs`
#![feature(never_type)]
// used in `edx.rs` and `emm.rs`
#![feature(associated_type_defaults)]
#![allow(unused_variables)]
#![feature(generic_const_exprs)]

#[macro_use]
mod macros;

mod callbacks;
mod chain_table;
mod edx;
mod emm;
mod entry_table;
mod error;
