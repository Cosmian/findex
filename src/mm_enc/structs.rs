use cosmian_crypto_core::kdf256;
use std::ops::Add;
use std::{
    collections::HashMap,
    fmt::{Debug, Display},
    hash::Hash,
    ops::{Deref, DerefMut},
};

use crate::CoreError;

use super::findex::{BLOCK_LENGTH, LINE_WIDTH, LINK_LENGTH};

pub struct Mm<Tag: Hash + PartialEq + Eq, Item>(HashMap<Tag, Vec<Item>>);

impl<Tag: Hash + PartialEq + Eq, Item> Default for Mm<Tag, Item> {
    fn default() -> Self {
        Self(HashMap::new())
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> Deref for Mm<Tag, Item> {
    type Target = HashMap<Tag, Vec<Item>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> DerefMut for Mm<Tag, Item> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<Tag: Hash + PartialEq + Eq + Clone, Item: Clone> Clone for Mm<Tag, Item> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Tag: Hash + PartialEq + Eq + Display, Item: Display> Display for Mm<Tag, Item> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Multi-Map: {{")?;
        for (tag, items) in self.iter() {
            writeln!(f, "  '{}': [", tag)?;
            for i in items {
                writeln!(f, "    '{}',", i)?;
            }
            writeln!(f, "  ],")?;
        }
        writeln!(f, "}}")
    }
}

impl<Tag: Hash + PartialEq + Eq + Debug, Item: Debug> Debug for Mm<Tag, Item> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mm: {:?}", self.0)
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> From<HashMap<Tag, Vec<Item>>> for Mm<Tag, Item> {
    fn from(value: HashMap<Tag, Vec<Item>>) -> Self {
        Self(value)
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> From<Mm<Tag, Item>> for HashMap<Tag, Vec<Item>> {
    fn from(value: Mm<Tag, Item>) -> Self {
        value.0
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> IntoIterator for Mm<Tag, Item> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = <<Self as Deref>::Target as IntoIterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Tag: Hash + PartialEq + Eq, Item> FromIterator<(Tag, Vec<Item>)> for Mm<Tag, Item> {
    fn from_iter<T: IntoIterator<Item = (Tag, Vec<Item>)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

impl<Tag: Hash + PartialEq + Eq, Item: PartialEq> PartialEq for Mm<Tag, Item> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

pub const METADATA_LENGTH: usize = 8;

#[derive(Clone, Debug)]
pub struct Metadata {
    pub start: u32,
    pub stop: u32,
}

impl Metadata {
    pub fn new(start: u32, stop: u32) -> Self {
        Self { start, stop }
    }

    pub fn unroll<const TAG_LENGTH: usize, Tag: From<[u8; TAG_LENGTH]> + Into<[u8; TAG_LENGTH]>>(
        &self,
        seed: &[u8],
    ) -> Vec<Tag> {
        (self.start..self.stop)
            .map(|pos| {
                let mut res = [0; TAG_LENGTH];
                kdf256!(&mut res, seed, &pos.to_be_bytes());
                res.into()
            })
            .collect()
    }
}

impl From<[u8; METADATA_LENGTH]> for Metadata {
    fn from(bytes: [u8; METADATA_LENGTH]) -> Self {
        let start =
            u32::from_be_bytes(<[u8; 4]>::try_from(&bytes[..4]).expect("correct byte length"));
        let stop =
            u32::from_be_bytes(<[u8; 4]>::try_from(&bytes[4..]).expect("correct byte length"));
        Self { start, stop }
    }
}

impl From<Metadata> for [u8; METADATA_LENGTH] {
    fn from(value: Metadata) -> Self {
        let mut res = [0; METADATA_LENGTH];
        res[..4].copy_from_slice(&value.start.to_be_bytes());
        res[4..].copy_from_slice(&value.stop.to_be_bytes());
        res
    }
}

impl Add<&Metadata> for &Metadata {
    type Output = Metadata;

    fn add(self, rhs: &Metadata) -> Self::Output {
        Self::Output {
            start: self.start + rhs.start,
            stop: self.stop + rhs.stop,
        }
    }
}

impl Display for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Metadata: {{ start: {}, stop: {} }}",
            self.start, self.stop
        )
    }
}

pub type Block = [u8; BLOCK_LENGTH];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link([u8; LINK_LENGTH]);

impl Link {
    pub fn new() -> Self {
        Self([0; LINK_LENGTH])
    }

    pub fn get_op(&self) -> Result<Operation, CoreError> {
        self.0[0].try_into()
    }

    pub fn set_op(&mut self, op: Operation) -> () {
        self.0[0] = op.into();
    }

    pub fn get_block(&self, pos: usize) -> Result<(Flag, &[u8]), CoreError> {
        if pos < LINE_WIDTH {
            Ok((
                Flag::try_from(self.0[1 + pos * (1 + BLOCK_LENGTH)])?,
                &self.0[2 + pos * (1 + BLOCK_LENGTH)..1 + (pos + 1) * (1 + BLOCK_LENGTH)],
            ))
        } else {
            Err(CoreError::Conversion(format!(
                "block position {pos} out of link range"
            )))
        }
    }

    pub fn set_block(&mut self, pos: usize, flag: Flag, block: &Block) -> Result<(), CoreError> {
        if pos < LINE_WIDTH {
            self.0[1 + pos * (1 + BLOCK_LENGTH)] = flag.try_into()?;
            self.0[2 + pos * (1 + BLOCK_LENGTH)..1 + (pos + 1) * (1 + BLOCK_LENGTH)]
                .copy_from_slice(block);
            Ok(())
        } else {
            Err(CoreError::Conversion(format!(
                "block position {pos} out of link range"
            )))
        }
    }
}

impl From<[u8; LINK_LENGTH]> for Link {
    fn from(bytes: [u8; LINK_LENGTH]) -> Self {
        Self(bytes)
    }
}

impl From<Link> for [u8; LINK_LENGTH] {
    fn from(link: Link) -> Self {
        link.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flag {
    Terminating(usize),
    Padding,
    NonTerminating,
}

impl TryFrom<Flag> for u8 {
    type Error = CoreError;

    fn try_from(flag: Flag) -> Result<Self, Self::Error> {
        match flag {
            Flag::Terminating(length) => <u8>::try_from(length).map_err(|_| {
                CoreError::Conversion(format!("`BLOCK_LENGTH` should be smaller than `u8::MAX`"))
            }),
            Flag::Padding => Ok(0),
            Flag::NonTerminating => Ok(255),
        }
    }
}

impl TryFrom<u8> for Flag {
    type Error = CoreError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            255 => Ok(Self::NonTerminating),
            0 => Ok(Self::Padding),
            length => {
                if (length as usize) < BLOCK_LENGTH {
                    Ok(Self::Terminating(length as usize))
                } else {
                    Err(CoreError::Conversion(format!(
                        "incorrect flag value {length}"
                    )))
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Insert,
    Delete,
}

impl From<Operation> for u8 {
    fn from(value: Operation) -> Self {
        match value {
            Operation::Insert => 1,
            Operation::Delete => 0,
        }
    }
}

impl TryFrom<u8> for Operation {
    type Error = CoreError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Delete),
            1 => Ok(Self::Insert),
            _ => Err(Self::Error::Conversion(format!(
                "byte value {value} cannot be converted into Operation"
            ))),
        }
    }
}
