use base64::engine::{general_purpose::STANDARD, Engine};
use cosmian_crypto_core::kdf256;
use std::{
    collections::HashMap,
    fmt::Display,
    ops::{Deref, DerefMut},
};

use crate::{dx_enc::Tag, BLOCK_LENGTH, LINE_WIDTH};

pub struct Mm<Item>(HashMap<Tag, Vec<Item>>);

impl<Item> Deref for Mm<Item> {
    type Target = HashMap<Tag, Vec<Item>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Item> DerefMut for Mm<Item> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<Item: AsRef<[u8]>> Display for Mm<Item> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Multi-Map: {{")?;
        for (tag, items) in self.iter() {
            writeln!(f, "  '{}': [", STANDARD.encode(tag))?;
            for i in items {
                writeln!(f, "    '{}',", STANDARD.encode(i))?;
            }
            writeln!(f, "  ],")?;
        }
        writeln!(f, "}}")
    }
}

impl<Item> From<HashMap<Tag, Vec<Item>>> for Mm<Item> {
    fn from(value: HashMap<Tag, Vec<Item>>) -> Self {
        Self(value)
    }
}

impl<Item> From<Mm<Item>> for HashMap<Tag, Vec<Item>> {
    fn from(value: Mm<Item>) -> Self {
        value.0
    }
}

impl<Item> IntoIterator for Mm<Item> {
    type IntoIter = <<Self as Deref>::Target as IntoIterator>::IntoIter;
    type Item = <<Self as Deref>::Target as IntoIterator>::Item;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Item> FromIterator<(Tag, Vec<Item>)> for Mm<Item> {
    fn from_iter<T: IntoIterator<Item = (Tag, Vec<Item>)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

pub const ENTRY_LENGTH: usize = 8;

#[derive(Clone)]
pub struct Metadata {
    pub start: u32,
    pub stop: u32,
}

impl Metadata {
    pub fn unroll<const LENGTH: usize>(&self, seed: &[u8]) -> Vec<[u8; LENGTH]> {
        (self.start..self.stop)
            .map(|pos| {
                let mut res = [0; LENGTH];
                kdf256!(&mut res, seed, &pos.to_be_bytes());
                res
            })
            .collect()
    }
}

impl From<&[u8; ENTRY_LENGTH]> for Metadata {
    fn from(bytes: &[u8; ENTRY_LENGTH]) -> Self {
        let start =
            u32::from_be_bytes(<[u8; 4]>::try_from(&bytes[..4]).expect("correct byte length"));
        let stop =
            u32::from_be_bytes(<[u8; 4]>::try_from(&bytes[4..]).expect("correct byte length"));
        Self { start, stop }
    }
}

impl From<&Metadata> for [u8; ENTRY_LENGTH] {
    fn from(entry: &Metadata) -> Self {
        let mut res = [0; ENTRY_LENGTH];
        res[..4].copy_from_slice(&entry.start.to_be_bytes());
        res[4..].copy_from_slice(&entry.stop.to_be_bytes());
        res
    }
}

pub const LINK_LENGTH: usize = 1 + LINE_WIDTH * (1 + BLOCK_LENGTH);
pub type Link = [u8; LINK_LENGTH];

pub enum Operation {
    Insert,
    Delete,
}
