use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    sync::{Arc, Mutex},
};

use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;
use tracing::debug;

use super::{FindexGraph, GxEnc};
use crate::{
    edx::Token,
    findex_mm::{CompactingData, ENTRY_LENGTH, LINK_LENGTH},
    CsRhDxEnc, DbInterfaceErrorTrait, Error, IndexedValue, Label,
};

impl<
        UserError: DbInterfaceErrorTrait,
        EntryTable: CsRhDxEnc<ENTRY_LENGTH, Error = Error<UserError>>,
        ChainTable: CsRhDxEnc<LINK_LENGTH, Error = Error<UserError>>,
    > FindexGraph<UserError, EntryTable, ChainTable>
{
    pub async fn list_indexed_encrypted_tags(&self) -> Result<Vec<Token>, Error<UserError>> {
        self.findex_mm.dump_entry_tokens().await
    }

    pub async fn prepare_compact<
        Tag: Debug + Hash + Eq + Clone + AsRef<[u8]> + From<Vec<u8>>,
        Value: Hash + Eq + Clone + From<Vec<u8>>,
    >(
        &self,
        key: &<Self as GxEnc<UserError>>::Key,
        tokens: HashSet<Token>,
        compact_target: &HashSet<Token>,
    ) -> Result<
        (
            HashMap<Token, HashSet<IndexedValue<Tag, Value>>>,
            CompactingData<ChainTable>,
        ),
        Error<UserError>,
    > {
        let (indexed_values, data) = self
            .findex_mm
            .prepare_compacting(key, tokens, compact_target)
            .await?;
        let indexed_values = indexed_values
            .into_iter()
            .map(|(token, value)| {
                value
                    .into_iter()
                    .map(|v| IndexedValue::<Tag, Value>::try_from(v.as_slice()))
                    .collect::<Result<_, _>>()
                    .map(|set| (token, set))
            })
            .collect::<Result<_, _>>()?;
        Ok((indexed_values, data))
    }

    pub async fn complete_compacting<
        Tag: Debug + Hash + Eq + Clone + AsRef<[u8]> + From<Vec<u8>>,
        Value: Hash + Eq + Clone + AsRef<[u8]> + From<Vec<u8>>,
    >(
        &self,
        rng: Arc<Mutex<impl CryptoRngCore>>,
        key: &<Self as GxEnc<UserError>>::Key,
        label: &Label,
        indexed_values: HashMap<Token, HashSet<IndexedValue<Tag, Value>>>,
        continuation: CompactingData<ChainTable>,
    ) -> Result<(), Error<UserError>> {
        debug!(
            "complete_compacting: entering: indexed_values number: {}",
            indexed_values.len()
        );
        let indexed_values = indexed_values
            .into_iter()
            .map(|(token, values)| (token, values.iter().map(Into::into).collect()))
            .collect();
        self.findex_mm
            .complete_compacting(rng, key, indexed_values, continuation, label)
            .await
    }
}
