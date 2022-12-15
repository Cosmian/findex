//! Defines generic parameters used in Findex interfaces.

use cosmian_crypto_core::symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, key::Key};

/// Length of an index table UID in bytes.
pub const UID_LENGTH: usize = 32;

/// Length of the blocks in the Chain Table in bytes.
pub const BLOCK_LENGTH: usize = 32;

/// Number of blocks per Chain Table value.
pub const TABLE_WIDTH: usize = 5;

/// Length of the Findex master key in bytes.
pub const MASTER_KEY_LENGTH: usize = 16;

/// Length of the chain keying material (`K_wi`) in bytes.
pub const KWI_LENGTH: usize = 16;

/// Length of a KMAC key in bytes.
pub const KMAC_KEY_LENGTH: usize = 32;

/// Length of a DEM key in bytes.
pub const DEM_KEY_LENGTH: usize = 32;

/// KMAC key type.
pub type KmacKey = Key<KMAC_KEY_LENGTH>;

/// DEM used in Findex.
pub type DemScheme = Aes256GcmCrypto;

/// Default number of results returned per keyword.
#[cfg(any(feature = "wasm_bindgen", feature = "ffi"))]
pub const MAX_RESULTS_PER_KEYWORD: usize = 65536; // around 2048 `indexed_values`
