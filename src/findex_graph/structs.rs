//! Structures used by `FindexGraph`.

use crate::error::CoreError;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum IndexedValue<Tag, Value> {
    Pointer(Tag),
    Data(Value),
}

impl<Tag, Value> IndexedValue<Tag, Value> {
    pub fn get_data(&self) -> Option<&Value> {
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

impl<Tag: AsRef<[u8]>, Value: AsRef<[u8]>> From<IndexedValue<Tag, Value>> for Vec<u8> {
    fn from(value: IndexedValue<Tag, Value>) -> Self {
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

impl<Tag: From<Vec<u8>>, Value: From<Vec<u8>>> TryFrom<&[u8]> for IndexedValue<Tag, Value> {
    type Error = CoreError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 2 {
            return Err(Self::Error::Conversion(format!(
                "indexed values should be at least two bytes long, {} given",
                value.len()
            )));
        }
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
