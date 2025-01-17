mod adt;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

#[cfg(test)]
pub use adt::tests;
pub use adt::{IndexADT, MemoryADT, VectorADT};
