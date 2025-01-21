mod interfaces;

pub use interfaces::{IndexADT, MemoryADT, VectorADT};

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

#[cfg(test)]
pub use interfaces::tests;
