pub use base64::engine::{
    general_purpose::{GeneralPurpose, STANDARD},
    Engine,
};
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
/// - `type_name`   : name of the byte-array type
macro_rules! impl_byte_array {
    ($type_name:ident, $length:expr, $str_name:expr) => {
        /// Byte array type.
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

/// Implements the functionalities of a byte-vector.
///
/// # Parameters
///
/// - `type_name`   : name of the byte-vector type
#[macro_export]
macro_rules! impl_byte_vector {
    ($type_name:ident, $str_name:expr) => {
        /// Byte vector type.
        #[derive(Clone, Debug, Default, Hash, PartialEq, Eq)]
        pub struct $type_name(Vec<u8>);

        impl $type_name {
            pub fn random(rng: &mut impl $crate::macros::CryptoRngCore) -> Self {
                let mut res = Self::default();
                rng.fill_bytes(&mut res);
                res
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

        impl From<Vec<u8>> for $type_name {
            fn from(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
        }

        impl From<$type_name> for Vec<u8> {
            fn from(var: $type_name) -> Self {
                var.0
            }
        }

        impl From<&str> for $type_name {
            fn from(s: &str) -> Self {
                Self(s.as_bytes().to_vec())
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

/// Creates a new [`Set`](crate::Set).
#[macro_export]
macro_rules! set {
    () => {
        $crate::Set::default()
    };
    ($($elt:expr $(,)?)+) => {
    $crate::Set::from_iter([$($elt,)+])
    }
}

/// Creates a new [DX](crate::Dx).
#[macro_export]
macro_rules! dx {
    () => {
        $crate::Dx::default()
    };
    ($($elt:expr $(,)?)+) => {
    $crate::Dx::from_iter([$($elt,)+])
    }
}

/// Creates a new [EDX](crate::Edx).
#[macro_export]
macro_rules! edx {
    () => {
        $crate::Edx::default()
    };
    ($($elt:expr $(,)?)+) => {
    $crate::Edx::from_iter([$($elt,)+])
    }
}

/// Creates a new [MM](crate::Mm).
#[macro_export]
macro_rules! mm {
    () => {
        $crate::Mm::default()
    };
    ($($elt:expr $(,)?)+) => {
    $crate::Mm::from_iter([$($elt,)+])
    }
}
