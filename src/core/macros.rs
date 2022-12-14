pub use tiny_keccak::{Hasher, IntoXof, Kmac, KmacXof, Xof};

/// Implements the functionalities of a byte-vector.
///
/// # Parameters
///
/// - `type_name`   : name of the byte-vector type
macro_rules! impl_byte_vector {
    ($type_name:ty) => {
        impl AsRef<[u8]> for $type_name {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Debug for $type_name {
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_fmt(format_args!("{}", base64::encode(&self.0)))
            }
        }

        impl Deref for $type_name {
            type Target = [u8];

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $type_name {
            #[inline]
            fn deref_mut(&mut self) -> &mut <Self as Deref>::Target {
                &mut self.0
            }
        }

        impl<'a> From<&'a [u8]> for $type_name {
            #[inline]
            fn from(bytes: &'a [u8]) -> Self {
                Self(bytes.to_vec())
            }
        }

        impl From<Vec<u8>> for $type_name {
            #[inline]
            fn from(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
        }

        impl From<&str> for $type_name {
            #[inline]
            fn from(bytes: &str) -> Self {
                bytes.as_bytes().into()
            }
        }

        impl From<$type_name> for Vec<u8> {
            #[inline]
            fn from(var: $type_name) -> Self {
                var.0
            }
        }

        /// `String` -> `$type_name` conversion parses the `String` in base 64.
        impl TryFrom<&String> for $type_name {
            type Error = FindexErr;

            #[inline]
            fn try_from(value: &String) -> Result<Self, Self::Error> {
                Ok(base64::decode(value)
                    .map_err(|e| Self::Error::ConversionError(e.to_string()))?
                    .into())
            }
        }

        impl Serializable for $type_name {
            type Error = FindexErr;

            #[inline]
            fn length(&self) -> usize {
                self.len()
            }

            #[inline]
            fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
                ser.write_vec(&self).map_err(Self::Error::from)
            }

            #[inline]
            fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
                Ok(Self::from(de.read_vec()?))
            }

            #[inline]
            fn try_to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
                // don't call `write()` to avoir writing size
                Ok(self.0.to_vec())
            }

            #[inline]
            fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
                // don't call `read()` since there is no leading size
                Ok(Self(bytes.to_vec()))
            }
        }
    };
}

/// Implements the functionalities of a (fixed-size) byte-array.
///
/// # Parameters
///
/// - `type_name`   : name of the byte-array type
macro_rules! impl_byte_array {
    ($type_name:ident) => {
        impl<const LENGTH: usize> AsRef<[u8]> for $type_name<LENGTH> {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl<const LENGTH: usize> std::fmt::Debug for $type_name<LENGTH> {
            #[inline]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_fmt(format_args!("{}", base64::encode(&self.0)))
            }
        }

        impl<const LENGTH: usize> std::ops::Deref for $type_name<LENGTH> {
            type Target = [u8];

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<const LENGTH: usize> std::ops::DerefMut for $type_name<LENGTH> {
            #[inline]
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl<const LENGTH: usize> From<[u8; LENGTH]> for $type_name<LENGTH> {
            #[inline]
            fn from(bytes: [u8; LENGTH]) -> Self {
                Self(bytes)
            }
        }

        impl<const LENGTH: usize> From<$type_name<LENGTH>> for [u8; LENGTH] {
            #[inline]
            fn from(var: $type_name<LENGTH>) -> Self {
                var.0
            }
        }

        impl<const LENGTH: usize> TryFrom<&str> for $type_name<LENGTH> {
            type Error = $crate::error::FindexErr;

            #[inline]
            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::try_from_bytes(
                    &base64::decode(value)
                        .map_err(|e| Self::Error::ConversionError(e.to_string()))?,
                )
            }
        }

        impl<const LENGTH: usize> Serializable for $type_name<LENGTH> {
            type Error = $crate::error::FindexErr;

            #[inline]
            fn length(&self) -> usize {
                LENGTH
            }

            #[inline]
            fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
                ser.write_array(&self).map_err(Self::Error::from)
            }

            #[inline]
            fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
                Ok(Self::from(de.read_array()?))
            }
        }
    };
}

/// KMAC hash algorithm used to derive keys.
///
/// - `length`  : length of the generated output
/// - `key`     : KMAC key
/// - `bytes`   : bytes to hash
#[macro_export]
macro_rules! kmac {
    ($length: ident, $key: expr, $($bytes: expr),+) => {
        {
            let mut kmac = tiny_keccak::Kmac::v128($key, b"");
            $(
                <$crate::core::macros::Kmac as $crate::core::macros::Hasher>::update(&mut kmac, $bytes);
            )*
            let mut xof = <$crate::core::macros::Kmac as $crate::core::macros::IntoXof>::into_xof(kmac);
            let mut res = [0; $length];
            <$crate::core::macros::KmacXof as $crate::core::macros::Xof>::squeeze(&mut xof, &mut res);
            res
        }
    };
}
