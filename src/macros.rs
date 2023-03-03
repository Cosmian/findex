pub use tiny_keccak::{self, Hasher, IntoXof, Kmac, KmacXof, Xof};

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

        impl Deref for $type_name {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $type_name {
            fn deref_mut(&mut self) -> &mut <Self as Deref>::Target {
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

        impl Serializable for $type_name {
            type Error = $crate::error::CoreError;

            fn length(&self) -> usize {
                self.len()
            }

            fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
                ser.write_vec(&self).map_err(Self::Error::from)
            }

            fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
                Ok(Self::from(de.read_vec()?))
            }

            fn try_to_bytes(&self) -> Result<Vec<u8>, Self::Error> {
                // don't call `write()` to avoir writing size
                Ok(self.0.to_vec())
            }

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
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl<const LENGTH: usize> std::ops::Deref for $type_name<LENGTH> {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<const LENGTH: usize> std::ops::DerefMut for $type_name<LENGTH> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl<const LENGTH: usize> From<[u8; LENGTH]> for $type_name<LENGTH> {
            fn from(bytes: [u8; LENGTH]) -> Self {
                Self(bytes)
            }
        }

        impl<const LENGTH: usize> From<$type_name<LENGTH>> for [u8; LENGTH] {
            fn from(var: $type_name<LENGTH>) -> Self {
                var.0
            }
        }

        impl<const LENGTH: usize> Serializable for $type_name<LENGTH> {
            type Error = $crate::error::CoreError;

            fn length(&self) -> usize {
                LENGTH
            }

            fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
                ser.write_array(&self).map_err(Self::Error::from)
            }

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

#[macro_export]
macro_rules! impl_findex_search {
    ($findex:ty, $error:ty) => {
        impl
            FindexSearch<
                { $crate::parameters::UID_LENGTH },
                { $crate::parameters::BLOCK_LENGTH },
                { $crate::parameters::TABLE_WIDTH },
                { $crate::parameters::MASTER_KEY_LENGTH },
                { $crate::parameters::KWI_LENGTH },
                { $crate::parameters::KMAC_KEY_LENGTH },
                { $crate::parameters::DEM_KEY_LENGTH },
                $crate::parameters::KmacKey,
                $crate::parameters::DemScheme,
                $error,
            > for $findex
        {
        }
    };
}

#[macro_export]
macro_rules! impl_findex_upsert {
    ($findex:ty, $error:ty) => {
        impl
            FindexUpsert<
                { $crate::parameters::UID_LENGTH },
                { $crate::parameters::BLOCK_LENGTH },
                { $crate::parameters::TABLE_WIDTH },
                { $crate::parameters::MASTER_KEY_LENGTH },
                { $crate::parameters::KWI_LENGTH },
                { $crate::parameters::KMAC_KEY_LENGTH },
                { $crate::parameters::DEM_KEY_LENGTH },
                $crate::parameters::KmacKey,
                $crate::parameters::DemScheme,
                $error,
            > for $findex
        {
        }
    };
}

#[macro_export]
macro_rules! impl_findex_compact {
    ($findex:ty, $error:ty) => {
        impl
            FindexCompact<
                { $crate::parameters::UID_LENGTH },
                { $crate::parameters::BLOCK_LENGTH },
                { $crate::parameters::TABLE_WIDTH },
                { $crate::parameters::MASTER_KEY_LENGTH },
                { $crate::parameters::KWI_LENGTH },
                { $crate::parameters::KMAC_KEY_LENGTH },
                { $crate::parameters::DEM_KEY_LENGTH },
                $crate::parameters::KmacKey,
                $crate::parameters::DemScheme,
                $error,
            > for $findex
        {
        }
    };
}
