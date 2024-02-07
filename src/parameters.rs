//! Defines parameters used by the Findex SSE scheme. These are parameters that
//! are not destined to be changed from one instantiation to another. Most of
//! them are linked to security considerations or scheme correctness.

/// Size of the Findex tag hash used. Only collision resistance is needed: 128
/// bits should be enough.
pub const HASH_LENGTH: usize = 32;

/// Length of the user key.
pub const USER_KEY_LENGTH: usize = 16;

/// Length of the blocks stored in the Chain Table.
pub const BLOCK_LENGTH: usize = 16;

/// Number of blocks stored per line of the Chain Table.
pub const LINE_WIDTH: usize = 5;
