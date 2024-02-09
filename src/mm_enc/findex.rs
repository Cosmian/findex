use std::fmt::Debug;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use cosmian_crypto_core::{kdf256, Secret};

use crate::{
    dx_enc::{CsRhDxEnc, Dx, DynRhDxEnc, Tag, TagSet},
    mm_enc::{structs::Metadata, CsRhMmEnc, ENTRY_LENGTH, LINK_LENGTH},
    CoreError, DbInterface, BLOCK_LENGTH, LINE_WIDTH, MIN_SEED_LENGTH,
};

use super::{
    structs::{Link, Mm, Operation},
    Error,
};

const INFO: &[u8] = b"Findex key derivation info.";

#[derive(Debug)]
pub struct Findex<EntryDxEnc: CsRhDxEnc<ENTRY_LENGTH>, ChainDxEnc: DynRhDxEnc<LINK_LENGTH>> {
    pub entry: EntryDxEnc,
    pub chain: ChainDxEnc,
}

impl<
        DbConnection: DbInterface + Clone,
        EntryDxEnc: CsRhDxEnc<ENTRY_LENGTH, DbConnection = DbConnection>,
        ChainDxEnc: DynRhDxEnc<LINK_LENGTH, DbConnection = EntryDxEnc::DbConnection>,
    > Findex<EntryDxEnc, ChainDxEnc>
{
    // This function is needed to create an error-unwrapping scope. I could not
    // find a cleaner way to do it.
    async fn rebuild_next(
        &self,
        entry_dx_enc: &EntryDxEnc,
        chain_dx_enc: &ChainDxEnc,
        entry_dx: Dx<ENTRY_LENGTH>,
    ) -> Result<(), Error<EntryDxEnc::Error, ChainDxEnc::Error>> {
        let chain_tags = entry_dx
            .iter()
            .flat_map(|(tag, bytes)| Metadata::from(bytes).unroll(tag))
            .collect::<TagSet>();

        let conflicting_entries =
            <EntryDxEnc as DynRhDxEnc<ENTRY_LENGTH>>::insert(entry_dx_enc, entry_dx)
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

    // This function is needed to create an error-unwrapping scope. I could not
    // find a cleaner way to do it.
    async fn rebuild_next_next(
        &self,
        chain_dx_enc: &ChainDxEnc,
        chain_dx: Dx<LINK_LENGTH>,
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

    /// Decomposes the given Findex index modifications into a sequence of Chain
    /// Table values.
    ///
    /// # Description
    ///
    /// Pads each value into blocks and push these blocks into a chain link,
    /// setting the flag bytes of each block according to the associated
    /// operation.
    pub(crate) fn decompose<const BLOCK_LENGTH: usize, const LINE_LENGTH: usize>(
        _op: Operation,
        _modifications: &[<Self as CsRhMmEnc>::Item],
    ) -> Result<Vec<Link>, CoreError> {
        todo!();
    }

    /// Recomposes the given sequence of Chain Table values into Findex values.
    /// No duplicated and no deleted value is returned.
    ///
    /// # Description
    ///
    /// Iterates over the blocks:
    /// - stacks the blocks until reading a terminating block;
    /// - merges the data from the stacked block and fill the stack;
    /// - if this value was an addition, adds it to the set, otherwise removes
    ///   any matching value from the set.
    pub(crate) fn recompose<const BLOCK_LENGTH: usize, const LINE_LENGTH: usize>(
        _chain: Vec<Link>,
    ) -> Result<Vec<<Self as CsRhMmEnc>::Item>, CoreError> {
        todo!();
    }

    /// Commits the given chain modifications into the Entry Table.
    ///
    /// Returns the chains to insert in the Chain Table.
    async fn commit(
        &self,
        dx: Dx<ENTRY_LENGTH>,
    ) -> Result<Dx<ENTRY_LENGTH>, <Self as CsRhMmEnc>::Error> {
        let (mut dx_cur, mut edx_cur) =
            <EntryDxEnc as CsRhDxEnc<ENTRY_LENGTH>>::insert(&self.entry, dx.clone())
                .await
                .map_err(Error::Entry)?;
        while !dx_cur.is_empty() {}
        Ok(dx)
    }
}

#[async_trait(?Send)]
impl<
        DbConnection: DbInterface + Clone,
        EntryDxEnc: CsRhDxEnc<ENTRY_LENGTH, DbConnection = DbConnection>,
        ChainDxEnc: DynRhDxEnc<LINK_LENGTH, DbConnection = EntryDxEnc::DbConnection>,
    > CsRhMmEnc for Findex<EntryDxEnc, ChainDxEnc>
{
    type DbConnection = EntryDxEnc::DbConnection;
    type Error = Error<EntryDxEnc::Error, ChainDxEnc::Error>;
    type Item = Vec<u8>;

    fn setup(seed: &[u8], connection: Self::DbConnection) -> Result<Self, Self::Error> {
        let mut findex_seed = Secret::<MIN_SEED_LENGTH>::default();
        kdf256!(&mut findex_seed, seed, INFO);
        let entry = EntryDxEnc::setup(seed, connection.clone()).map_err(Self::Error::Entry)?;
        let chain = ChainDxEnc::setup(seed, connection).map_err(Self::Error::Chain)?;
        Ok(Self { entry, chain })
    }

    async fn search(&self, tags: TagSet) -> Result<Mm<Self::Item>, Self::Error> {
        let metadata = self.entry.get(tags).await.map_err(Self::Error::Entry)?;
        let chain_tags = metadata
            .into_iter()
            .map(|(tag, bytes)| (tag, Metadata::from(&bytes).unroll(&tag)))
            .collect::<Mm<Tag>>();
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
                let items = Self::recompose::<BLOCK_LENGTH, LINE_WIDTH>(links)?;
                Ok((entry_tag, items))
            })
            .collect()
    }

    async fn insert(&self, mm: Mm<Self::Item>) -> Result<(), Self::Error> {
        let mm = mm
            .into_iter()
            .map(|(tag, items)| {
                Self::decompose::<BLOCK_LENGTH, LINE_WIDTH>(Operation::Insert, &items)
                    .map(|chain| (tag, chain))
            })
            .collect::<Result<Mm<Link>, _>>()?;
        // self.push(mm)
        todo!()
    }

    async fn delete(&self, mm: Mm<Self::Item>) -> Result<(), Self::Error> {
        let mm = mm
            .into_iter()
            .map(|(tag, items)| {
                Self::decompose::<BLOCK_LENGTH, LINE_WIDTH>(Operation::Delete, &items)
                    .map(|chain| (tag, chain))
            })
            .collect::<Result<Mm<Link>, _>>()?;
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
        let entry_tags = entry_dx.keys().copied().collect::<TagSet>();

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
            })
        }
    }
}
