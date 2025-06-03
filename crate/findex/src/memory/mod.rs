mod encryption_layer;
pub use encryption_layer::{KEY_LENGTH, MemoryEncryptionLayer};

#[cfg(any(test, feature = "test-utils"))]
mod in_memory;
#[cfg(any(test, feature = "test-utils"))]
pub use in_memory::InMemory;
