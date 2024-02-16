use std::{
    collections::{HashSet, LinkedList},
    fmt::{Debug, Display},
    hash::Hash,
    marker::PhantomData,
    ops::DerefMut,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use cosmian_crypto_core::{kdf256, Secret};

use crate::{
    dx_enc::{CsRhDxEnc, Dx, DynRhDxEnc, Set},
    mm_enc::{structs::Metadata, CsRhMmEnc, METADATA_LENGTH},
    CoreError, MIN_SEED_LENGTH,
};

use super::{
    structs::{Block, Flag, Link, Mm, Operation},
    Error,
};

pub const BLOCK_LENGTH: usize = 16;
pub const LINE_WIDTH: usize = 5;
pub const LINK_LENGTH: usize = 1 + LINE_WIDTH * (1 + BLOCK_LENGTH);

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

    // A linked list stored in a set could advantageously replace this
    // code. However there is no such structure in the standard library and I
    // don't want to include a dependency for that. Since I also don't want to
    // implement a dedicated structure for now, this will do.
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

/// Findex is a CS-RH-MM-Enc scheme.
///
/// It relies on a generic CS-RH-DX-Enc and a generic Dyn-RH-DX-Enc schemes.
#[derive(Debug)]
pub struct Findex<
    const TAG_LENGTH: usize,
    Tag: Hash + PartialEq + Eq + From<[u8; TAG_LENGTH]> + Into<[u8; TAG_LENGTH]>,
    EntryDxEnc: CsRhDxEnc<TAG_LENGTH, METADATA_LENGTH, Tag, Item = Metadata>,
    ChainDxEnc: DynRhDxEnc<LINK_LENGTH, Item = Link>,
> {
    pub entry: EntryDxEnc,
    pub chain: ChainDxEnc,
    tag: PhantomData<Tag>,
}

impl<
        const TAG_LENGTH: usize,
        Tag: Hash
            + PartialEq
            + Eq
            + From<[u8; TAG_LENGTH]>
            + Into<[u8; TAG_LENGTH]>
            + AsRef<[u8]>
            + Clone
            + Display,
        EntryDxEnc: CsRhDxEnc<TAG_LENGTH, METADATA_LENGTH, Tag, Item = Metadata>,
        ChainDxEnc: DynRhDxEnc<LINK_LENGTH, Tag = Tag, Item = Link>,
    > Findex<TAG_LENGTH, Tag, EntryDxEnc, ChainDxEnc>
{
    /// Commits the given chain modifications into the Entry Table.
    ///
    /// Returns the chains to insert in the Chain Table.
    async fn reserve(
        &self,
        dx: Dx<METADATA_LENGTH, Tag, Metadata>,
    ) -> Result<Dx<METADATA_LENGTH, Tag, Metadata>, Error<EntryDxEnc::Error, ChainDxEnc::Error>>
    {
        let mut modified_dx = dx.clone();
        let (mut dx_curr, mut edx_curr) = <EntryDxEnc as CsRhDxEnc<
            TAG_LENGTH,
            METADATA_LENGTH,
            Tag,
        >>::insert(&self.entry, dx.clone())
        .await
        .map_err(Error::Entry)?;

        while !dx_curr.is_empty() {
            let mut dx_new = Dx::<METADATA_LENGTH, Tag, Metadata>::default();
            for (tag, metadata_cur) in dx_curr {
                let metadata = dx.get(&tag).ok_or_else(|| {
                    Error::Core(CoreError::Crypto(format!(
                        "returned tag '{tag}' does not match any tag in the input DX"
                    )))
                })?;
                let metadata_new = metadata + &metadata_cur;
                modified_dx.get_mut(&tag).and_then(|metadata| {
                    *metadata = metadata_new.clone();
                    Some(())
                });
                dx_new.deref_mut().insert(tag, metadata_new);
            }
            (dx_curr, edx_curr) =
                <EntryDxEnc as CsRhDxEnc<TAG_LENGTH, METADATA_LENGTH, Tag>>::upsert(
                    &self.entry,
                    edx_curr,
                    dx_new,
                )
                .await
                .map_err(Error::Entry)?;
        }
        Ok(modified_dx)
    }

    /// Extracts modifications to the Entry DX associated to the addition and
    /// deletion of the given MM.
    ///
    /// Adding a sequence of links for a given tag increases the `stop` counter
    /// in the associated metadata. Removing a sequence of links for a given tag
    /// increases the `start` counter in the associated metadata.
    fn extract_entry_modifications(
        &self,
        additions: &Mm<Tag, Link>,
        deletions: &Mm<Tag, Link>,
    ) -> Result<Dx<METADATA_LENGTH, Tag, Metadata>, Error<EntryDxEnc::Error, ChainDxEnc::Error>>
    {
        let mut new_entry_dx = Dx::<METADATA_LENGTH, Tag, Metadata>::default();
        for (tag, chain) in &**additions {
            let n_links = <u32>::try_from(chain.len())
                .map_err(|_| Error::Core(CoreError::Conversion("chain overflow".to_string())))?;
            new_entry_dx
                .deref_mut()
                .insert(tag.clone(), Metadata::new(0, n_links));
        }
        for (tag, chain) in &**deletions {
            let n_links = <u32>::try_from(chain.len())
                .map_err(|_| Error::Core(CoreError::Conversion("chain overflow".to_string())))?;
            new_entry_dx
                .entry(tag.clone())
                .and_modify(|metadata| metadata.start += n_links)
                .or_insert(Metadata::new(n_links, 0));
        }
        Ok(new_entry_dx)
    }

    fn extract_chain_additions(
        &self,
        metadata: &Dx<METADATA_LENGTH, Tag, Metadata>,
        additions: Mm<Tag, Link>,
    ) -> Result<Dx<LINK_LENGTH, Tag, Link>, Error<EntryDxEnc::Error, ChainDxEnc::Error>> {
        let mut added_chain_dx = Dx::<LINK_LENGTH, Tag, Link>::default();
        for (entry_tag, new_links) in additions {
            let n_links = <u32>::try_from(new_links.len())
                .map_err(|_| Error::Core(CoreError::Conversion("chain overflow".to_string())))?;
            let metadata = metadata.get(&entry_tag).ok_or_else(|| {
                Error::Core(CoreError::Crypto(format!(
                    "no metadata found in the reserved DX for tag {entry_tag}"
                )))
            })?;
            added_chain_dx.extend(
                Metadata::new(metadata.stop - n_links, metadata.stop)
                    .unroll(entry_tag.as_ref())
                    .into_iter()
                    .zip(new_links),
            )
        }
        Ok(added_chain_dx)
    }

    fn extract_chain_deletions(
        &self,
        metadata: &Dx<METADATA_LENGTH, Tag, Metadata>,
        deletions: Mm<Tag, Link>,
    ) -> Result<Set<Tag>, Error<EntryDxEnc::Error, ChainDxEnc::Error>> {
        let mut deleted_chain_tags = Set::<Tag>::default();
        for (entry_tag, new_links) in deletions {
            let n_links = <u32>::try_from(new_links.len())
                .map_err(|_| Error::Core(CoreError::Conversion("chain overflow".to_string())))?;
            let metadata = metadata.get(&entry_tag).ok_or_else(|| {
                Error::Core(CoreError::Crypto(format!(
                    "no metadata found in the reserved DX for tag {entry_tag}"
                )))
            })?;
            deleted_chain_tags.extend(
                Metadata::new(metadata.stop + n_links, metadata.stop)
                    .unroll(entry_tag.as_ref())
                    .into_iter(),
            )
        }
        Ok(deleted_chain_tags)
    }

    /// Applies the given additions and deletions to the stored MM.
    ///
    /// Removes any inserted links in case an error occurs during the insertion.
    async fn apply(
        &self,
        additions: Mm<Tag, Link>,
        deletions: Mm<Tag, Link>,
    ) -> Result<(), Error<EntryDxEnc::Error, ChainDxEnc::Error>> {
        let entry_modifications = self.extract_entry_modifications(&additions, &deletions)?;
        let modified_dx = self.reserve(entry_modifications).await?;
        let inserted_links = self.extract_chain_additions(&modified_dx, additions)?;
        let inserted_link_tags = inserted_links.keys().cloned().collect();

        let insertion_result = self
            .chain
            .insert(inserted_links)
            .await
            .map_err(Error::Chain)
            .and_then(|conclicting_links| {
                if !conclicting_links.is_empty() {
                    Err(Error::Core(CoreError::Crypto(
                        "conflicts when inserting new links".to_string(),
                    )))
                } else {
                    Ok(())
                }
            });

        if insertion_result.is_ok() {
            // Go on with deleting links.
            let deleted_links = self.extract_chain_deletions(&modified_dx, deletions)?;
            self.chain.delete(deleted_links).await.map_err(Error::Chain)
        } else {
            // Reverts any successful insertion. Do not revert entry
            // modifications as concurrent modifications could have
            // happened.
            self.chain
                .delete(inserted_link_tags)
                .await
                .map_err(Error::Chain)?;
            insertion_result
        }
    }
}

impl<
        const TAG_LENGTH: usize,
        Tag: Hash
            + PartialEq
            + Eq
            + From<[u8; TAG_LENGTH]>
            + Into<[u8; TAG_LENGTH]>
            + AsRef<[u8]>
            + Clone
            + Display,
        EntryDxEnc: CsRhDxEnc<TAG_LENGTH, METADATA_LENGTH, Tag, Item = Metadata>,
        ChainDxEnc: DynRhDxEnc<LINK_LENGTH, Tag = Tag, Item = Link>,
    > CsRhMmEnc for Findex<TAG_LENGTH, Tag, EntryDxEnc, ChainDxEnc>
{
    type DbConnection = (EntryDxEnc::DbConnection, ChainDxEnc::DbConnection);
    type Error = Error<EntryDxEnc::Error, ChainDxEnc::Error>;
    type Tag = Tag;
    type Item = Vec<u8>;

    fn setup(seed: &[u8], connection: Self::DbConnection) -> Result<Self, Self::Error> {
        let mut findex_seed = Secret::<MIN_SEED_LENGTH>::default();
        kdf256!(&mut findex_seed, seed, INFO);
        let entry = EntryDxEnc::setup(seed, connection.0).map_err(Self::Error::Entry)?;
        let chain = ChainDxEnc::setup(seed, connection.1).map_err(Self::Error::Chain)?;
        let tag = PhantomData::default();
        Ok(Self { entry, chain, tag })
    }

    async fn search(&self, tags: Set<Tag>) -> Result<Mm<Self::Tag, Self::Item>, Self::Error> {
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
        let new_links = mm
            .into_iter()
            .map(|(tag, items)| decompose(Operation::Insert, &items).map(|chain| (tag, chain)))
            .collect::<Result<Mm<EntryDxEnc::Tag, Link>, _>>()?;
        self.apply(new_links, Mm::default()).await
    }

    async fn delete(&self, mm: Mm<Self::Tag, Self::Item>) -> Result<(), Self::Error> {
        let new_links = mm
            .into_iter()
            .map(|(tag, items)| decompose(Operation::Delete, &items).map(|chain| (tag, chain)))
            .collect::<Result<Mm<EntryDxEnc::Tag, Link>, _>>()?;
        self.apply(new_links, Mm::default()).await
    }

    async fn compact(&self) -> Result<(), Self::Error> {
        todo!()
    }

    async fn rebuild(
        &self,
        seed: &[u8],
        connection: Self::DbConnection,
    ) -> Result<Self, Self::Error> {
        let mut findex_seed = Secret::<MIN_SEED_LENGTH>::default();
        kdf256!(&mut findex_seed, seed, INFO);
        let entry = self
            .entry
            .rebuild(&*findex_seed, connection.0)
            .await
            .map_err(Self::Error::Entry)?;
        let chain = self
            .chain
            .rebuild(&*findex_seed, connection.1)
            .await
            .map_err(Self::Error::Chain)?;
        let tag = PhantomData::default();
        Ok(Self { entry, chain, tag })
    }
}

#[cfg(all(test, feature = "in_memory"))]
mod tests {

    use std::{collections::HashMap, thread::spawn};

    use cosmian_crypto_core::CsRng;
    use futures::executor::block_on;
    use rand::{RngCore, SeedableRng};

    use crate::{
        dx_enc::{Tag, Vera},
        InMemoryDb,
    };

    use super::*;

    const N_WORKERS: usize = 100;

    #[test]
    fn decomposition() {
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

        // Assert all elements are recovered, without the duplicated and deleted
        // ones.
        assert_eq!(recomposed_value.len(), 2);
        assert!(added_value.contains(&recomposed_value[0]));
        assert!(added_value.contains(&recomposed_value[1]));
        // Assert the order is preserved.
        assert_eq!(recomposed_value[0], added_value[0]);
        assert_eq!(recomposed_value[1], added_value[2]);
    }

    /// Checks the insert, delete and fetch work correctly in a sequential
    /// manner:
    /// - successive add work;
    /// - delete works;
    /// - reinserting existing item in a chain works;
    /// - fetch finds all the chains, all the items, and the order of the items
    ///   is correct.
    #[test]
    fn insert_then_fetch() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::<32>::random(&mut rng);
        let entry_db = InMemoryDb::default();
        let chain_db = InMemoryDb::default();
        let findex = Findex::<
            { Tag::LENGTH },
            Tag,
            Vera<METADATA_LENGTH, InMemoryDb, Metadata>,
            Vera<LINK_LENGTH, InMemoryDb, Link>,
        >::setup(&*seed, (entry_db, chain_db))
        .unwrap();

        let inserted_mm = (0..N_WORKERS)
            .map(|i| {
                let tag = Tag::random(&mut rng);
                let data = (0..=i as u8).map(|j| vec![j]).collect::<Vec<_>>();
                let mm = Mm::from(HashMap::from_iter([(tag, data.clone())]));
                block_on(findex.insert(mm.clone()))?;
                Ok((i, mm))
            })
            .collect::<Result<HashMap<_, _>, Error<_, _>>>()
            .unwrap();

        let mut inserted_mm = inserted_mm
            .into_values()
            .flat_map(|mm| mm.into_iter())
            .collect::<Mm<Tag, Vec<u8>>>();

        let fetched_mm =
            block_on(findex.search(inserted_mm.keys().copied().collect::<Set<Tag>>())).unwrap();
        assert_eq!(inserted_mm, fetched_mm);

        // Now remove some entries, add some already existing
        let removed_data = (0..N_WORKERS)
            .zip(inserted_mm.iter())
            .map(|(i, (tag, data))| {
                // Select a random data.
                let pos = rng.next_u32() as usize % data.len();
                let mm = Mm::from(HashMap::from_iter([(tag.clone(), vec![data[pos].clone()])]));
                block_on(findex.delete(mm))?;
                Ok((i, (tag.clone(), data[pos].clone())))
            })
            .collect::<Result<HashMap<_, _>, Error<_, _>>>()
            .unwrap();

        let mut reinserted_data = (0..N_WORKERS)
            .zip(inserted_mm.iter())
            .map(|(i, (tag, data))| {
                // Select a random data.
                let pos = rng.next_u32() as usize % data.len();
                let mm = Mm::from(HashMap::from_iter([(tag.clone(), vec![data[pos].clone()])]));
                block_on(findex.insert(mm))?;
                Ok((i, (tag.clone(), data[pos].clone())))
            })
            .collect::<Result<HashMap<_, _>, Error<_, _>>>()
            .unwrap();

        for worker in 0..N_WORKERS {
            let (_, deletion) = removed_data.get(&worker).unwrap();
            let (tag, addition) = reinserted_data.remove(&worker).unwrap();
            let data = inserted_mm.get_mut(&tag).unwrap();
            data.retain(|item| item != deletion);
            data.retain(|item| *item != addition);
            data.push(addition);
        }

        let fetched_mm =
            block_on(findex.search(inserted_mm.keys().copied().collect::<Set<Tag>>())).unwrap();
        assert_eq!(inserted_mm, fetched_mm);
    }

    #[test]
    fn concurrent_additions() {
        let mut rng = CsRng::from_entropy();
        let db = (InMemoryDb::default(), InMemoryDb::default());
        let seed = Secret::<32>::random(&mut rng);

        let tag = Tag::random(&mut rng);

        let handles = (0..N_WORKERS)
            .map(|i| {
                let db = db.clone();
                let seed = seed.clone();
                let mm = Mm::<Tag, Vec<u8>>::from(HashMap::from_iter([(
                    tag.clone(),
                    vec![vec![i as u8]],
                )]));
                spawn(move || -> Result<(), Error<_, _>> {
                    let findex = Findex::<
                        { Tag::LENGTH },
                        Tag,
                        Vera<METADATA_LENGTH, InMemoryDb, Metadata>,
                        Vera<LINK_LENGTH, InMemoryDb, Link>,
                    >::setup(&*seed, db)
                    .unwrap();
                    block_on(findex.insert(mm))
                })
            })
            .collect::<Vec<_>>();

        for h in handles {
            h.join().unwrap().unwrap();
        }

        let findex = Findex::<
            { Tag::LENGTH },
            Tag,
            Vera<METADATA_LENGTH, InMemoryDb, Metadata>,
            Vera<LINK_LENGTH, InMemoryDb, Link>,
        >::setup(&*seed, db)
        .unwrap();

        let stored_mm = block_on(findex.search(Set::from_iter([tag.clone()]))).unwrap();
        let stored_ids = stored_mm
            .get(&tag)
            .unwrap()
            .iter()
            .cloned()
            .collect::<HashSet<_>>();

        assert_eq!(
            stored_ids,
            (0..N_WORKERS as u8)
                .map(|id| vec![id])
                .collect::<HashSet<Vec<u8>>>()
        );
    }

    #[test]
    fn test_rebuild() {
        let mut rng = CsRng::from_entropy();
        let seed = Secret::<32>::random(&mut rng);
        let db = (InMemoryDb::default(), InMemoryDb::default());
        let findex = Findex::<
            { Tag::LENGTH },
            Tag,
            Vera<METADATA_LENGTH, InMemoryDb, Metadata>,
            Vera<LINK_LENGTH, InMemoryDb, Link>,
        >::setup(&*seed, db)
        .unwrap();

        let inserted_mm = (0..N_WORKERS)
            .map(|i| {
                let tag = Tag::random(&mut rng);
                let data = (0..=i as u8).map(|j| vec![j]).collect::<Vec<_>>();
                let mm = Mm::from(HashMap::from_iter([(tag, data.clone())]));
                block_on(findex.insert(mm.clone()))?;
                Ok((i, mm))
            })
            .collect::<Result<HashMap<_, _>, Error<_, _>>>()
            .unwrap();

        let inserted_mm = inserted_mm
            .into_values()
            .flat_map(|mm| mm.into_iter())
            .collect::<Mm<Tag, Vec<u8>>>();

        let seed = Secret::<32>::random(&mut rng);
        let db = (InMemoryDb::default(), InMemoryDb::default());
        let findex = block_on(findex.rebuild(&*seed, db)).unwrap();
        let fetched_mm =
            block_on(findex.search(inserted_mm.keys().copied().collect::<Set<Tag>>())).unwrap();
        assert_eq!(inserted_mm, fetched_mm);
    }
}
