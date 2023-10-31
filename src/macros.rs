pub use core::ops::{Deref, DerefMut};

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

/// Implements the functionalities of a byte-vector.
///
/// # Parameters
///
/// - `type_name`   : name of the byte-vector type
macro_rules! impl_byte_vector {
    ($type_name:ty) => {
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

        impl<'a> From<&'a [u8]> for $type_name {
            fn from(bytes: &'a [u8]) -> Self {
                Self(bytes.to_vec())
            }
        }

        impl From<Vec<u8>> for $type_name {
            fn from(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
        }

        impl From<&str> for $type_name {
            fn from(bytes: &str) -> Self {
                bytes.as_bytes().into()
            }
        }

        impl From<$type_name> for Vec<u8> {
            fn from(var: $type_name) -> Self {
                var.0
            }
        }

        impl std::fmt::Display for $type_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{:?}", String::from_utf8_lossy(&self.0))
            }
        }
    };
}
