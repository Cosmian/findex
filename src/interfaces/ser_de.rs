use std::{collections::HashSet, hash::Hash};

use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable, Serializer};

use crate::error::FindexErr;

pub fn serialize_set<T: Serializable<Error = FindexErr>>(
    set: &HashSet<T>,
) -> Result<Vec<u8>, FindexErr> {
    let mut serializer = Serializer::default();
    serializer.write_u64(set.len() as u64)?;
    for key in set {
        key.write(&mut serializer)?;
    }
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
