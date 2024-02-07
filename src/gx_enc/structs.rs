//! Structures used by `FindexGraph`.

use std::fmt::Display;

use crate::error::CoreError;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum IndexedValue<Tag, Data> {
    Pointer(Tag),
    Data(Data),
}

impl<Tag: Display, Data: Display> Display for IndexedValue<Tag, Data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pointer(keyword) => write!(f, "IndexedValue::Pointer({keyword})"),
            Self::Data(data) => write!(f, "IndexedValue::Data({data})"),
        }
    }
}

impl<Tag, Data> IndexedValue<Tag, Data> {
    pub fn get_data(&self) -> Option<&Data> {
        match self {
            Self::Pointer(_) => None,
            Self::Data(data) => Some(data),
        }
    }

    pub fn get_pointer(&self) -> Option<&Tag> {
        match self {
            Self::Pointer(pointer) => Some(pointer),
            Self::Data(_) => None,
        }
    }

    pub fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_))
    }
}

impl<Tag: AsRef<[u8]>, Data: AsRef<[u8]>> From<&IndexedValue<Tag, Data>> for Vec<u8> {
    fn from(value: &IndexedValue<Tag, Data>) -> Self {
        match value {
            IndexedValue::Pointer(pointer) => {
                let pointer = pointer.as_ref();
                let mut b = Self::with_capacity(pointer.len() + 1);
                b.push(b'w');
                b.extend(pointer);
                b
            }
            IndexedValue::Data(data) => {
                let data = data.as_ref();
                let mut b = Self::with_capacity(data.len() + 1);
                b.push(b'l');
                b.extend(data);
                b
            }
        }
    }
}

impl<Tag: From<Vec<u8>>, Data: From<Vec<u8>>> TryFrom<&[u8]> for IndexedValue<Tag, Data> {
    type Error = CoreError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 2 {
            return Err(Self::Error::Conversion(format!(
                "indexed values should be at least two bytes long, {} given",
                value.len()
            )));
        }
        // TODO: change the leading value in v.7
        match value[0] {
            b'w' => Ok(Self::Pointer(value[1..].to_vec().into())),
            b'l' => Ok(Self::Data(value[1..].to_vec().into())),
            _ => Err(Self::Error::Conversion(format!(
                "indexed value should start by {} or {}, not `{}`",
                b'w', b'l', &value[0]
            ))),
        }
    }
}
