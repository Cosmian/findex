use crate::{Error, F32Vector, LocalitySensitiveHash, VectorDB};
use cosmian_findex::IndexADT;
use std::{collections::HashSet, hash::Hash};

/// Implementation of a vector DB based on an LSH scheme and an index.
///
/// The LSH is instantiated K times, but a single index is used. The LSH tables
/// are therefore virtual tables: their ID is used in the key and is akin to a
/// domain-separation parameter.
///
/// If the underlying LSH scheme returns multiple probes, those probes are used
/// in a symmetric way for both inserting to and searching from the DB.
pub struct LshVectorDB<const D: usize, Lsh, Index>
where
    Lsh: LocalitySensitiveHash<Input = F32Vector<D>>,
    Lsh::Output: Send + Sync + Clone + Eq + Hash,
    Index: IndexADT<Lsh::Output, Lsh::Input>,
{
    lsh: Lsh,
    index: Index,
}

impl<const D: usize, Lsh, Index> VectorDB<Lsh::Input> for LshVectorDB<D, Lsh, Index>
where
    Lsh: LocalitySensitiveHash<Input = F32Vector<D>>,
    Lsh::Output: Send + Sync + Clone + Eq + Hash,
    Index: IndexADT<Lsh::Output, Lsh::Input>,
{
    type Parameters = (Lsh, Index);
    type Vector = Lsh::Input;
    type Score = f32;
    type Error = Error;

    fn init(params: Self::Parameters) -> Result<Self, Self::Error> {
        Ok(Self {
            lsh: params.0,
            index: params.1,
        })
    }

    async fn search(
        &self,
        k: usize,
        query: &Self::Vector,
    ) -> Result<Vec<(Self::Vector, Self::Score)>, Error> {
        let mut candidates = HashSet::new();
        for probe in self.lsh.hash(query) {
            let new_candidates = self
                .index
                .search(&probe)
                .await
                .map_err(|e| Error(format!("index error: {e}")))?;
            for c in new_candidates {
                candidates.insert(c);
            }
        }
        Ok(query.mips(k, candidates))
    }

    async fn insert(&self, point: Self::Vector) -> Result<(), Error> {
        for probe in self.lsh.hash(&point) {
            self.index
                .insert(probe, [point.clone()])
                .await
                .map_err(|e| Error(format!("index error: {e}")))?;
        }
        Ok(())
    }
}
