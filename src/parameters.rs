//! Defines generic parameters used in Findex interfaces.

use core::num::NonZeroUsize;

use cosmian_crypto_core::symmetric_crypto::{aes_256_gcm_pure::Aes256GcmCrypto, key::Key};

/// Length of an index table UID in bytes.
pub const UID_LENGTH: usize = 32;

/// Length of the blocks in the Chain Table in bytes.
pub const BLOCK_LENGTH: usize = 32;

/// Number of blocks per Chain Table value.
pub const CHAIN_TABLE_WIDTH: usize = 5;

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

pub const SECURE_FETCH_CHAINS_BATCH_SIZE: NonZeroUsize = unsafe { NonZeroUsize::new_unchecked(1) };
