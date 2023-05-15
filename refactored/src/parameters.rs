//! Defines parameters used by the Findex SSE scheme. These are parameters that
//! are not destined to be changed from one instanciation to another. Most of
//! them are linked to security considerations or scheme correctness.

/// Size of the label hash used. Since these hashes are not exposed, their size
/// reflects the need to prevent collision: 128 bits should be enough.
pub const HASH_LENGTH: usize = 16;

/// Seed used to derive the keys. Only collision resistance is needed: 128 bits
/// should be enough.
pub const SEED_LENGTH: usize = 16;

/// Size of the token used. It is 256 bits in order to allow more than 80 bits
/// of post-quantum resistance.
pub const TOKEN_LENGTH: usize = 32;
