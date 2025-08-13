#[cfg(feature = "batch")]
pub mod batching_layer {
    mod error;
    mod memory;

    pub use error::BatchingLayerError;
    pub use memory::{BatcherArc, MemoryBatcher};
}

#[cfg(feature = "batch")]
pub use batching_layer::*;
