//! Structures used by `FindexMultiMap`.

use std::{
    collections::HashMap,
    hash::Hash,
    ops::{Deref, DerefMut},
};

use crate::{
    edx::{DxEnc, Token},
    error::CoreError,
    parameters::{BLOCK_LENGTH, HASH_LENGTH, LINE_WIDTH, SEED_LENGTH, TOKEN_LENGTH},
};

/// Operation allowed to be performed on a multi-map.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Operation {
    Addition,
    Deletion,
}

/// Value stored in the Entry Table by Findex.
///
/// It is composed of a:
/// - Chain Table seed;
/// - Entry Table tag;
/// - counter (u32).
pub const ENTRY_LENGTH: usize = SEED_LENGTH + HASH_LENGTH + TOKEN_LENGTH;

#[derive(Clone)]
pub struct Entry<ChainTable: DxEnc<LINK_LENGTH>> {
    pub seed: ChainTable::Seed,
    pub tag_hash: [u8; HASH_LENGTH],
    pub chain_token: Option<Token>,
}

impl<ChainTable: DxEnc<LINK_LENGTH>> Entry<ChainTable> {
    pub fn new(
        seed: ChainTable::Seed,
        tag_hash: [u8; HASH_LENGTH],
        chain_token: Option<Token>,
    ) -> Self {
        Self {
            seed,
            tag_hash,
            chain_token,
        }
    }
}
impl<ChainTable: DxEnc<LINK_LENGTH>> From<Entry<ChainTable>> for [u8; ENTRY_LENGTH] {
    fn from(value: Entry<ChainTable>) -> Self {
        let mut res = [0; ENTRY_LENGTH];
        res[..TOKEN_LENGTH].copy_from_slice(
            value
                .chain_token
                .unwrap_or_else(|| Token::from([0; TOKEN_LENGTH]))
                .as_ref(),
        );
        res[TOKEN_LENGTH..TOKEN_LENGTH + SEED_LENGTH].copy_from_slice(value.seed.as_ref());
        res[TOKEN_LENGTH + SEED_LENGTH..].copy_from_slice(&value.tag_hash);
        res
    }
}

impl<ChainTable: DxEnc<LINK_LENGTH>> From<[u8; ENTRY_LENGTH]> for Entry<ChainTable>
where
    [(); 1 + (BLOCK_LENGTH + 1) * LINE_WIDTH]:,
{
    fn from(value: [u8; ENTRY_LENGTH]) -> Self {
        let mut chain_token = [0; TOKEN_LENGTH];
        chain_token.copy_from_slice(&value[..TOKEN_LENGTH]);
        let mut seed = ChainTable::Seed::default();
        seed.as_mut()
            .copy_from_slice(&value[TOKEN_LENGTH..TOKEN_LENGTH + SEED_LENGTH]);
        let mut tag_hash = [0; HASH_LENGTH];
        tag_hash.copy_from_slice(&value[TOKEN_LENGTH + SEED_LENGTH..]);
        Self {
            seed,
            tag_hash,
            chain_token: if [0; TOKEN_LENGTH] == chain_token {
                None
            } else {
                Some(Token::from(chain_token))
            },
        }
    }
}

pub const LINK_LENGTH: usize = 1 + (BLOCK_LENGTH + 1) * LINE_WIDTH;

/// Value stored in the Chain Table by Findex.
///
/// It is composed of a list of:
/// - one operation byte;
/// - a list of `LINE_LENGTH` blocks of:
///     - one length byte;
///     - `BLOCK_LENGTH` data bytes.
///
/// The operation byte is used to write all the type bits operation bits into a
/// single byte rather than adding an entire byte per block.
///
/// The length byte is used to store the length of the data written into the
/// block. The value `255` is used to mark the block as *non-terminating*. A
/// non-terminating block can only be full.
#[derive(Debug)]
pub struct Link(pub [u8; LINK_LENGTH]);

impl Link {
    /// Creates an empty Chain Table value.
    pub fn new() -> Self {
        Self([0; LINK_LENGTH])
    }

    /// Returns:
    /// - `true` if the `pos`th block is a terminating block;
    /// - the data stored in this block.
    pub fn get_block(&self, pos: usize) -> Result<(bool, &[u8]), CoreError> {
        if pos > LINE_WIDTH {
            return Err(CoreError::Crypto(format!(
                "cannot query a block at pos ({pos}) greater than the line length ({LINE_WIDTH})"
            )));
        }
        let block = &self.0[(1 + pos * (BLOCK_LENGTH + 1))..=((pos + 1) * (BLOCK_LENGTH + 1))];
        if block[0] == 255 {
            Ok((false, &block[1..]))
        } else {
            Ok((true, &block[1..=usize::from(block[0])]))
        }
    }

    /// Writes the given data into the `pos`th block. Mark it as terminating if
    /// `is_terminating` is set to `true`.
    pub fn set_block(
        &mut self,
        pos: usize,
        data: &[u8],
        is_terminating: bool,
    ) -> Result<(), CoreError> {
        if pos > LINE_WIDTH {
            return Err(CoreError::Crypto(format!(
                "cannot modify a block at pos ({pos}) greater than the line length ({LINE_WIDTH})"
            )));
        }
        let block = &mut self.0[(1 + pos * (BLOCK_LENGTH + 1))..=((pos + 1) * (BLOCK_LENGTH + 1))];
        if is_terminating {
            block[0] = u8::try_from(data.len())?;
        } else {
            block[0] = 255;
        }
        block[1..=data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Returns the operation associated to the `pos`th block.
    pub fn get_operation(&self, pos: usize) -> Result<Operation, CoreError> {
        if pos > LINE_WIDTH {
            return Err(CoreError::Crypto(format!(
                "cannot query a block at pos ({pos}) greater than the line length ({LINE_WIDTH})"
            )));
        }
        if (self.0[0] >> pos) & 1 == 1 {
            Ok(Operation::Addition)
        } else {
            Ok(Operation::Deletion)
        }
    }

    /// Sets the operation associated to the `pos`th block.
    pub fn set_operation(&mut self, pos: usize, op: Operation) -> Result<(), CoreError> {
        if pos > LINE_WIDTH {
            return Err(CoreError::Crypto(format!(
                "cannot modify a block at pos ({pos}) greater than the line length ({LINE_WIDTH})"
            )));
        }
        if Operation::Addition == op {
            self.0[0] |= 1 << pos;
        }
        Ok(())
    }
}

impl Deref for Link {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Link {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct CompactingData<ChainTable: DxEnc<LINK_LENGTH>> {
    #[allow(clippy::type_complexity)]
    pub(crate) metadata: HashMap<Token, (ChainTable::Key, Vec<Token>)>,
    pub(crate) entries: HashMap<Token, Entry<ChainTable>>,
}
