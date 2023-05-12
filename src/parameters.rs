//! Defines parameters used by the Findex SSE scheme. These are parameters that
//! are not destined to be changed from one instanciation to another. Most of
//! them are linked to security considerations or scheme correctness.

use cosmian_crypto_core::Aes256Gcm;

/// Size of the Findex tag hash used. Only collision resistance is needed: 128
/// bits should be enough.
pub const HASH_LENGTH: usize = 32;

/// Seed used to derive the keys. Only collision resistance is needed: 128 bits
/// should be enough.
pub const SEED_LENGTH: usize = 16;

/// Size of the token used. It is 256 bits in order to allow more than 80 bits
/// of post-quantum resistance.
pub const TOKEN_LENGTH: usize = 32;

/// Length of the user key.
pub const USER_KEY_LENGTH: usize = 16;

/// Length of the symmetric encryption keys used.
pub const SYM_KEY_LENGTH: usize = Aes256Gcm::KEY_LENGTH;

/// Length of the MAC tags used.
pub const MAC_LENGTH: usize = Aes256Gcm::MAC_LENGTH;

/// Length of the nonces used.
pub const NONCE_LENGTH: usize = Aes256Gcm::NONCE_LENGTH;

/// Length of the blocks stored in the Chain Table.
pub const BLOCK_LENGTH: usize = 16;

/// Number of blocks stored per line of the Chain Table.
pub const LINE_WIDTH: usize = 5;
