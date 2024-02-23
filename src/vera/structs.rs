use std::{fmt::Debug, hash::Hash};

use crate::CoreError;

/// Size of the tags used by Vera. It is 128-bit to avoid collisions.
const TAG_LENGTH: usize = 16;
impl_byte_array!(Tag, TAG_LENGTH, "Tag");

impl TryFrom<&[u8]> for Tag {
    type Error = CoreError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; Self::LENGTH]>::try_from(bytes)
            .map_err(|_| {
                Self::Error::Conversion(format!(
                    "incorrect byte length: expected {}, found {}",
                    Self::LENGTH,
                    bytes.len()
                ))
            })
            .map(Self)
    }
}
