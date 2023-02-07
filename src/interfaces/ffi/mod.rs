//! Defines the FFI interface for Findex.

pub mod api;
pub mod core;

/// Maximum number of bytes used by a LEB128 encoding.
const LEB128_MAXIMUM_ENCODED_BYTES_NUMBER: usize = 8;

/// Limit on the recursion to use when none is provided.
// TODO (TBZ): is this parameter really necessary? It is used when the
// `max_depth` parameter given is less than 0 => shouldn't an error be returned
// instead ?
pub const MAX_DEPTH: usize = 100; // 100 should always be enough
