pub use base64::engine::{general_purpose::{GeneralPurpose, STANDARD}, Engine};
pub use core::{
    default::Default,
    ops::{Deref, DerefMut},
};
pub use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;
pub use tiny_keccak::{self, Hasher, IntoXof, Kmac, KmacXof, Xof};

/// Hashes the given bytes to the desired length using the KMAC algorithm and
/// the given key.
///
/// - `length`  : length of the generated output
/// - `key`     : KMAC key
/// - `bytes`   : bytes to hash
#[macro_export]
macro_rules! kmac {
    ($length: ident, $key: expr, $($bytes: expr),+) => {
        {
            let mut kmac = $crate::macros::tiny_keccak::Kmac::v256($key, b"");
            $(
                <$crate::macros::Kmac as $crate::macros::Hasher>::update(&mut kmac, $bytes);
            )*
            let mut xof = <$crate::macros::Kmac as $crate::macros::IntoXof>::into_xof(kmac);
            let mut res = [0; $length];
            <$crate::macros::KmacXof as $crate::macros::Xof>::squeeze(&mut xof, &mut res);
            res
        }
    };
}

/// Implements the functionalities of a byte-array.
///
/// # Parameters
///
/// - `type_name`   : name of the byte-vector type
macro_rules! impl_byte_array {
    ($type_name:ident, $length:expr, $str_name:expr) => {
        #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
        pub struct $type_name([u8; $length]);

        impl $type_name {
            pub const LENGTH: usize = $length;

            pub fn random(rng: &mut impl $crate::macros::CryptoRngCore) -> Self {
                let mut res = Self::default();
                rng.fill_bytes(&mut res);
                res
            }
        }

        impl $crate::macros::Default for $type_name {
            fn default() -> Self {
                Self([0; $length])
            }
        }

        impl AsRef<[u8]> for $type_name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl $crate::macros::Deref for $type_name {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl $crate::macros::DerefMut for $type_name {
            fn deref_mut(&mut self) -> &mut <Self as $crate::macros::Deref>::Target {
                &mut self.0
            }
        }

        impl From<[u8; $length]> for $type_name {
            fn from(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }
        }

        impl From<$type_name> for [u8; $length] {
            fn from(var: $type_name) -> Self {
                var.0
            }
        }

        impl std::fmt::Display for $type_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{}({})",
                    $str_name,
                    <$crate::macros::GeneralPurpose as $crate::macros::Engine>::encode(
                        &$crate::macros::STANDARD,
                        self
                    )
                )
            }
        }
    };
}
