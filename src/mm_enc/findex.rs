use std::{
    collections::{HashSet, LinkedList},
    fmt::Debug,
    hash::Hash,
    marker::PhantomData,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use cosmian_crypto_core::{kdf256, Secret};

use crate::{
    dx_enc::{CsRhDxEnc, Dx, DynRhDxEnc, TagSet},
    mm_enc::{structs::Metadata, CsRhMmEnc, ENTRY_LENGTH, LINK_LENGTH},
    CoreError, DbInterface, BLOCK_LENGTH, LINE_WIDTH, MIN_SEED_LENGTH,
};

use super::{
    structs::{Block, Flag, Link, Mm, Operation},
    Error,
};

const INFO: &[u8] = b"Findex key derivation info.";

/// Groups the given bytes into `BLOCK_LENGTH`-byte blocks.
///
/// Uses a flag to distinguish full terminating block from a non-terminating
/// block.
fn bytes_to_blocks(mut bytes: &[u8]) -> Result<Vec<(Flag, Block)>, CoreError> {
    let mut blocks = Vec::new();
    loop {
        if bytes.len() > BLOCK_LENGTH {
            let mut block = Block::default();
            block.copy_from_slice(&bytes[..BLOCK_LENGTH]);
            blocks.push((Flag::NonTerminating, block));
            bytes = &bytes[BLOCK_LENGTH..];
        } else {
            let mut block = Block::default();
            block[..bytes.len()].copy_from_slice(bytes);
            blocks.push((Flag::Terminating(bytes.len()), block));
            return Ok(blocks);
        }
    }
}

/// Decomposes the given sequence of byte-values into a sequence of links.
///
/// # Description
///
/// Groups value bytes into `BLOCK_LENGTH`-byte blocks. Use padding on the last
/// one if needed. Then groups the blocks into `LINE_WIDTH`-length
/// links. Prepends each block with a flag used to distinguish terminating,
/// padding, and non-terminating blocks. Use padding blocks on the last link if
/// needed. Prepends each link with the given operation.
fn decompose(op: Operation, modifications: &[Vec<u8>]) -> Result<Vec<Link>, CoreError> {
    let mut blocks = modifications
        .iter()
        .flat_map(|item| bytes_to_blocks(item))
        .flatten();

    // This algorithm is not the most efficient as is needs a second pass on
    // the blocks to group them into links. This could have been done while
    // creating the blocks, but decoupling these operations seemed clearer to
    // me.
    let mut chain = Vec::<Link>::new();

    loop {
        let mut link = Link::new();
        link.set_op(op);
        for pos in 0..LINE_WIDTH {
            if let Some((flag, block)) = blocks.next() {
                link.set_block(pos, flag, &block)?;
            } else {
                if pos != 0 {
                    // Add incomplete links if some blocks were added.
                    chain.push(link);
                }
                return Ok(chain);
            }
        }
        chain.push(link);
    }
}

/// Recomposes the given sequence links into a sequence of byte values.
/// No duplicated and no deleted value is returned.
///
/// # Description
///
/// Iterates over the blocks:
/// - stacks the blocks until reading a terminating block;
/// - merges the data from the stacked block and fill the stack;
///
/// Then iterates over the value from the end, and keeps only valid items,
/// without duplicates.
fn recompose(chain: &[Link]) -> Result<Vec<Vec<u8>>, CoreError> {
    let mut value = Vec::<(Operation, Vec<u8>)>::new();
    let mut stack = Vec::default();
    for link in chain {
        let op = link.get_op()?;
        for pos in 0..LINE_WIDTH {
            let (flag, block) = link.get_block(pos)?;
            match flag {
                Flag::Padding => (),
                Flag::NonTerminating => stack.push(block),
                Flag::Terminating(length) => {
                    stack.push(&block[..length]);
                    let item = stack.concat();
                    value.push((op, item));
                    stack.clear();
                }
            }
        }
    }

    // In order to conserve order, a set cannot be used. Since removing elements
    // from a vector is expensive, I used a linked list. However, the return
    // type is a vector, thus the linked list needs to be converted. All in all,
    // this method adds two iterations/allocations: there may be a better
    // way. Maybe sticking with vectors is the way to go.
    let mut purged_value = LinkedList::new();
    let mut remaining_items = HashSet::new();
    let mut deleted_items = HashSet::new();
    for (op, item) in value.into_iter().rev() {
        if op == Operation::Insert && !deleted_items.contains(&item) {
            if !remaining_items.contains(&item) {
                purged_value.push_front(item.clone());
                remaining_items.insert(item);
            }
        } else {
            deleted_items.insert(item);
        }
    }
    Ok(purged_value.into_iter().collect())
}

#[derive(Debug)]
pub struct Findex<
    const TAG_LENGTH: usize,
    Tag: Hash + PartialEq + Eq + From<[u8; TAG_LENGTH]> + Into<[u8; TAG_LENGTH]>,
    EntryDxEnc: CsRhDxEnc<TAG_LENGTH, ENTRY_LENGTH, Tag>,
    ChainDxEnc: DynRhDxEnc<LINK_LENGTH>,
> {
    pub entry: EntryDxEnc,
    pub chain: ChainDxEnc,
    tag: PhantomData<Tag>,
}

impl<
        DbConnection: DbInterface + Clone,
        const TAG_LENGTH: usize,
        Tag: Hash
            + PartialEq
            + Eq
            + From<[u8; TAG_LENGTH]>
            + Into<[u8; TAG_LENGTH]>
            + AsRef<[u8]>
            + Clone,
        EntryDxEnc: CsRhDxEnc<TAG_LENGTH, ENTRY_LENGTH, Tag, DbConnection = DbConnection, Item = Metadata>,
        ChainDxEnc: DynRhDxEnc<LINK_LENGTH, DbConnection = EntryDxEnc::DbConnection, Tag = Tag, Item = Link>,
    > Findex<TAG_LENGTH, Tag, EntryDxEnc, ChainDxEnc>
{
    // This function is needed to create an error-unwrapping sub-scope for the
    // rebuild operation. I could not find a better way to do it.
    async fn rebuild_next(
        &self,
        entry_dx_enc: &EntryDxEnc,
        chain_dx_enc: &ChainDxEnc,
        entry_dx: Dx<ENTRY_LENGTH, Tag, Metadata>,
    ) -> Result<(), Error<EntryDxEnc::Error, ChainDxEnc::Error>> {
        let chain_tags = entry_dx
            .iter()
            .flat_map(|(tag, value)| value.unroll(tag.as_ref()))
            .collect::<TagSet<ChainDxEnc::Tag>>();

        let conflicting_entries =
            <EntryDxEnc as DynRhDxEnc<ENTRY_LENGTH>>::insert(&entry_dx_enc, entry_dx)
                .await
                .map_err(Error::Entry)?;

        if !conflicting_entries.is_empty() {
            return Err(Error::Core(CoreError::Crypto(
                "conflicting entries after rekeying: maybe try with a new seed".to_string(),
            )));
        }

        let chain_dx = self
            .chain
            .get(chain_tags.clone())
            .await
            .map_err(Error::Chain)?;

        // From this point, an error means the new EMM cannot be created but the
        // new Chain EDX has been inserted. It must be deleted before returning
        // the error.
        let res = self.rebuild_next_next(chain_dx_enc, chain_dx).await;
        if let Err(err) = res {
            chain_dx_enc.delete(chain_tags).await.map_err(|e| {
                CoreError::Crypto(format!(
                    "while backtracking after error {err}, delete Chain tokens with error {e}"
                ))
            })?;
            Err(err)
        } else {
            Ok(())
        }
    }

    // This function is needed to create an error-unwrapping sub-scope for the
    // rebuild-next operation. I could not find a better way to do it.
    async fn rebuild_next_next(
        &self,
        chain_dx_enc: &ChainDxEnc,
        chain_dx: Dx<LINK_LENGTH, Tag, Link>,
    ) -> Result<(), Error<EntryDxEnc::Error, ChainDxEnc::Error>> {
        let conflicting_entries = chain_dx_enc.insert(chain_dx).await.map_err(Error::Chain)?;
        if !conflicting_entries.is_empty() {
            Err(Error::Core(CoreError::Crypto(
                "conflicting links after rekeying: maybe try with a new seed".to_string(),
            )))
        } else {
            Ok(())
        }
    }

    /// Commits the given chain modifications into the Entry Table.
    ///
    /// Returns the chains to insert in the Chain Table.
    async fn _commit(
        &self,
        _dx: Dx<ENTRY_LENGTH, Tag, Metadata>,
    ) -> Result<Dx<ENTRY_LENGTH, Tag, Metadata>, <Self as CsRhMmEnc>::Error> {
        todo!()
        // let (mut _dx_cur, mut _edx_cur) = <EntryDxEnc as CsRhDxEnc<
        //     TAG_LENGTH,
        //     ENTRY_LENGTH,
        //     Tag,
        // >>::insert(&self.entry, dx.clone())
        // .await
        // .map_err(Error::Entry)?;
        // while !dx_cur.is_empty() {}
        // Ok(dx)
    }
}

#[async_trait(?Send)]
impl<
        const TAG_LENGTH: usize,
        Tag: Hash
            + PartialEq
            + Eq
            + From<[u8; TAG_LENGTH]>
            + Into<[u8; TAG_LENGTH]>
            + AsRef<[u8]>
            + Clone,
        DbConnection: DbInterface + Clone,
        EntryDxEnc: CsRhDxEnc<TAG_LENGTH, ENTRY_LENGTH, Tag, DbConnection = DbConnection, Item = Metadata>,
        ChainDxEnc: DynRhDxEnc<LINK_LENGTH, DbConnection = EntryDxEnc::DbConnection, Tag = Tag, Item = Link>,
    > CsRhMmEnc for Findex<TAG_LENGTH, Tag, EntryDxEnc, ChainDxEnc>
{
    type DbConnection = EntryDxEnc::DbConnection;
    type Error = Error<EntryDxEnc::Error, ChainDxEnc::Error>;
    type Tag = Tag;
    type Item = Vec<u8>;

    fn setup(seed: &[u8], connection: Self::DbConnection) -> Result<Self, Self::Error> {
        let mut findex_seed = Secret::<MIN_SEED_LENGTH>::default();
        kdf256!(&mut findex_seed, seed, INFO);
        let entry = EntryDxEnc::setup(seed, connection.clone()).map_err(Self::Error::Entry)?;
        let chain = ChainDxEnc::setup(seed, connection).map_err(Self::Error::Chain)?;
        let tag = PhantomData::default();
        Ok(Self { entry, chain, tag })
    }

    async fn search(&self, tags: TagSet<Tag>) -> Result<Mm<Self::Tag, Self::Item>, Self::Error> {
        let metadata = self.entry.get(tags).await.map_err(Self::Error::Entry)?;
        let chain_tags = metadata
            .into_iter()
            .map(|(tag, bytes)| {
                let chain_tags = bytes.unroll(&tag.as_ref());
                (tag, chain_tags)
            })
            .collect::<Mm<EntryDxEnc::Tag, ChainDxEnc::Tag>>();
        let links = self
            .chain
            .get(chain_tags.values().flatten().cloned().collect())
            .await
            .map_err(Self::Error::Chain)?;
        chain_tags
            .into_iter()
            .map(|(entry_tag, chain_tags)| {
                let links = chain_tags
                    .into_iter()
                    .map(|chain_tag| {
                        links
                            .get(&chain_tag)
                            .ok_or_else(|| {
                                CoreError::Crypto(format!(
                                    "missing link value for chain tag {}",
                                    STANDARD.encode(chain_tag)
                                ))
                            })
                            .copied()
                    })
                    .collect::<Result<Vec<Link>, _>>()?;
                let items = recompose(&links)?;
                Ok((entry_tag, items))
            })
            .collect()
    }

    async fn insert(&self, mm: Mm<Self::Tag, Self::Item>) -> Result<(), Self::Error> {
        let _mm = mm
            .into_iter()
            .map(|(tag, items)| decompose(Operation::Insert, &items).map(|chain| (tag, chain)))
            .collect::<Result<Mm<EntryDxEnc::Tag, Link>, _>>()?;
        // self.push(mm)
        todo!()
    }

    async fn delete(&self, mm: Mm<Self::Tag, Self::Item>) -> Result<(), Self::Error> {
        let _mm = mm
            .into_iter()
            .map(|(tag, items)| decompose(Operation::Delete, &items).map(|chain| (tag, chain)))
            .collect::<Result<Mm<EntryDxEnc::Tag, Link>, _>>()?;
        // self.push(mm)
        todo!()
    }

    async fn compact(&self) -> Result<(), Self::Error> {
        todo!()
    }

    async fn rebuild(mut self, seed: &[u8]) -> Result<Self, Self::Error> {
        let mut findex_seed = Secret::<MIN_SEED_LENGTH>::default();
        kdf256!(&mut findex_seed, seed, INFO);
        let new_entry_dx_enc = self.entry.rekey(&findex_seed).map_err(Self::Error::Entry)?;
        let new_chain_dx_enc = self.chain.rekey(&findex_seed).map_err(Self::Error::Chain)?;

        let entry_dx = self.entry.dump().await.map_err(Self::Error::Entry)?;
        let entry_tags = entry_dx
            .keys()
            .cloned()
            .collect::<TagSet<EntryDxEnc::Tag>>();

        // From this point, an error means the new EMM cannot be created but the
        // new Entry EDX has been inserted. It must be deleted before returning
        // the error.
        let res = self
            .rebuild_next(&new_entry_dx_enc, &new_chain_dx_enc, entry_dx)
            .await;
        if let Err(err) = res {
            new_entry_dx_enc.delete(entry_tags).await.map_err(|e| {
                CoreError::Crypto(format!(
                    "while backtracking after error {err}, delete Entry tokens with error {e}"
                ))
            })?;
            Err(err)
        } else {
            Ok(Self {
                entry: new_entry_dx_enc,
                chain: new_chain_dx_enc,
                tag: PhantomData::default(),
            })
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_decomposition() {
        let added_value = vec![
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            "I am a very long test string".as_bytes().to_vec(),
            "I am a second very long test string".as_bytes().to_vec(),
        ];
        let deleted_value = vec![
            "I am a deleted-only string".as_bytes().to_vec(),
            "I am a very long test string".as_bytes().to_vec(),
        ];

        let mut chain = decompose(Operation::Insert, &added_value).unwrap();
        chain.extend_from_slice(&decompose(Operation::Insert, &added_value).unwrap());
        chain.extend_from_slice(&decompose(Operation::Delete, &deleted_value).unwrap());
        let recomposed_value = recompose(&chain).unwrap();

        // Assert all elements are recovered, that without the duplicated and
        // deleted ones.
        assert_eq!(recomposed_value.len(), 2);
        assert!(added_value.contains(&recomposed_value[0]));
        assert!(added_value.contains(&recomposed_value[1]));
        // Assert the order is preserved.
        assert_eq!(recomposed_value[0], added_value[0]);
        assert_eq!(recomposed_value[1], added_value[2]);
    }
}
