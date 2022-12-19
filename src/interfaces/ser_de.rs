use std::{collections::HashSet, hash::Hash};

use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable, Serializer};

use crate::error::FindexErr;

pub fn serialize_set<T: Serializable<Error = FindexErr>>(
    set: &HashSet<T>,
) -> Result<Vec<u8>, FindexErr> {
    let mut serializer = Serializer::default();
    serializer.write(&SerializableSet(set))?;
    Ok(serializer.finalize())
}

pub fn deserialize_set<T: Serializable<Error = FindexErr> + Eq + Hash>(
    set: &[u8],
) -> Result<HashSet<T>, FindexErr> {
    let mut deserializer = Deserializer::new(set);
    let length = <usize>::try_from(deserializer.read_u64()?)?;
    let mut set = HashSet::with_capacity(length);
    for _ in 0..length {
        set.insert(T::read(&mut deserializer)?);
    }
    if deserializer.finalize().is_empty() {
        Ok(set)
    } else {
        Err(FindexErr::ConversionError(
            "Remaining bytes after UID set deserialization!".to_string(),
        ))
    }
}

/// Wrap a `HashSet` of `Serializable` to make it `Serializable` itself
///
/// This struct cannot be used to deserialize `HashSet`s. Use `deserialize_set`
pub struct SerializableSet<'a, T>(pub &'a HashSet<T>)
where
    T: Serializable<Error = FindexErr>;

impl<'a, T> Serializable for SerializableSet<'a, T>
where
    T: Serializable<Error = FindexErr>,
{
    type Error = FindexErr;

    fn length(&self) -> usize {
        0
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut len = ser.write_u64(self.0.len() as u64)?;
        for key in self.0 {
            len += key.write(ser)?;
        }
        Ok(len)
    }

    fn read(_de: &mut Deserializer) -> Result<Self, Self::Error> {
        Err(FindexErr::Other(
            "SerializableSet cannot be used to deserialize HashSets. Use deserialize_set"
                .to_owned(),
        ))
    }
}
