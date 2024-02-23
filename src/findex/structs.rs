use cosmian_crypto_core::kdf256;
use std::ops::Add;
use std::{
    fmt::{Debug, Display},
    hash::Hash,
};

use crate::CoreError;

#[derive(Clone, Debug)]
pub struct Metadata {
    pub start: u32,
    pub stop: u32,
}

impl Metadata {
    pub const LENGTH: usize = 8;

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

impl From<[u8; Self::LENGTH]> for Metadata {
    fn from(bytes: [u8; Self::LENGTH]) -> Self {
        let start =
            u32::from_be_bytes(<[u8; 4]>::try_from(&bytes[..4]).expect("correct byte length"));
        let stop =
            u32::from_be_bytes(<[u8; 4]>::try_from(&bytes[4..]).expect("correct byte length"));
        Self { start, stop }
    }
}

impl From<Metadata> for [u8; Metadata::LENGTH] {
    fn from(value: Metadata) -> Self {
        let mut res = [0; Metadata::LENGTH];
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

pub const BLOCK_LENGTH: usize = 16;
impl_byte_array!(Block, BLOCK_LENGTH, "Block");

pub const LINE_WIDTH: usize = 5;

pub const LINK_LENGTH: usize = 1 + LINE_WIDTH * (1 + BLOCK_LENGTH);
impl_byte_array!(Link, LINK_LENGTH, "Link");

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
