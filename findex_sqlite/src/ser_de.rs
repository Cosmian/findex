use std::{collections::HashSet, hash::Hash};

use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable, Serializer};

use crate::Error;

pub fn serialize_set<
    SerializationError: std::error::Error,
    T: Serializable<Error = SerializationError> + Eq + Hash,
>(
    set: &HashSet<T>,
) -> Result<Vec<u8>, Error>
where
    crate::Error: From<SerializationError>,
{
    let mut serializer = Serializer::default();
    serializer.write(&SerializableSet(set))?;
    Ok(serializer.finalize())
}

pub fn deserialize_set<
    SerializationError: std::error::Error,
    T: Serializable<Error = SerializationError> + Eq + Hash,
>(
    set: &[u8],
) -> Result<HashSet<T>, Error>
where
    crate::Error: From<SerializationError>,
{
    let mut deserializer = Deserializer::new(set);
    let length = <usize>::try_from(deserializer.read_leb128_u64()?)?;
    let mut set = HashSet::with_capacity(length);
    for _ in 0..length {
        set.insert(T::read(&mut deserializer)?);
    }
    if deserializer.finalize().is_empty() {
        Ok(set)
    } else {
        Err(Error::SerializationError(
            "Remaining bytes after UID set deserialization!".to_string(),
        ))
    }
}

/// Wrap a `HashSet` of `Serializable` to make it `Serializable` itself
///
/// This struct cannot be used to deserialize `HashSet`s. Use `deserialize_set`
pub struct SerializableSet<'a, SerializationError, T>(pub &'a HashSet<T>)
where
    SerializationError: std::error::Error,
    crate::Error: From<SerializationError>,
    T: Serializable<Error = SerializationError>;

impl<'a, SerializationError, T> Serializable for SerializableSet<'a, SerializationError, T>
where
    SerializationError: std::error::Error,
    crate::Error: From<SerializationError>,
    T: Serializable<Error = SerializationError>,
{
    type Error = Error;

    fn length(&self) -> usize {
        0
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut len = ser.write_leb128_u64(self.0.len() as u64)?;
        for key in self.0 {
            len += key.write(ser)?;
        }
        Ok(len)
    }

    fn read(_de: &mut Deserializer) -> Result<Self, Self::Error> {
        Err(Error::SerializationError(
            "SerializableSet cannot be used to deserialize HashSets. Use deserialize_set"
                .to_string(),
        ))
    }
}
