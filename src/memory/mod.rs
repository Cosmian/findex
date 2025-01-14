mod encryption_layer;
mod in_memory_store;

pub use encryption_layer::MemoryEncryptionLayer;
#[cfg(any(test, feature = "bench"))]
pub use in_memory_store::InMemory;
