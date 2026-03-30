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
pub struct Vdb<const D: usize, Lsh, Index>
where
    Lsh: LocalitySensitiveHash<Input = F32Vector<D>>,
    Lsh::Probe: Send + Sync + Clone + Eq + Hash,
    Index: IndexADT<Lsh::Probe, (Lsh::Input, String)>,
{
    lsh: Lsh,
    index: Index,
    iprobe: Option<usize>,
    qprobe: Option<usize>,
}

pub struct VDBParameters<Lsh, Index> {
    pub lsh: Lsh,
    pub index: Index,
    pub iprobe: Option<usize>,
    pub qprobe: Option<usize>,
}

impl<const D: usize, Lsh, Index> VectorDB for Vdb<D, Lsh, Index>
where
    Lsh: Send + Sync + LocalitySensitiveHash<Input = F32Vector<D>>,
    Lsh::Probe: Send + Sync + Clone + Eq + Hash,
    Index: Send + Sync + IndexADT<Lsh::Probe, (Lsh::Input, String)>,
{
    type Parameters = VDBParameters<Lsh, Index>;
    type Vector = Lsh::Input;
    type MetaData = String;
    type Score = f32;
    type Error = Error;

    fn init(params: Self::Parameters) -> Result<Self, Error> {
        Ok(Self {
            lsh: params.lsh,
            index: params.index,
            iprobe: params.iprobe,
            qprobe: params.qprobe,
        })
    }

    async fn query(
        &self,
        k: usize,
        query: &Self::Vector,
    ) -> Result<Vec<((Self::Vector, Self::MetaData), Self::Score)>, Error> {
        let mut candidates = HashSet::new();
        for probes in self
            .lsh
            .hash(query, self.qprobe)
            .map_err(|e| Error(e.to_string()))?
        {
            for (probe, _score) in probes {
                let new_candidates = self
                    .index
                    .search(&probe)
                    .await
                    .map_err(|e| Error(format!("index error: {e}")))?;
                for c in new_candidates {
                    candidates.insert(c);
                }
            }
        }
        let results = query.mips_with(|(c, _)| c, k, candidates);
        Ok(results)
    }

    async fn insert(&self, point: Self::Vector, data: Self::MetaData) -> Result<(), Error> {
        for probes in self
            .lsh
            .hash(&point, self.iprobe)
            .map_err(|e| Error(e.to_string()))?
        {
            for (probe, _score) in probes {
                self.index
                    .insert(probe, [(point.clone(), data.clone())])
                    .await
                    .map_err(|e| Error(format!("index error: {e}")))?;
            }
        }
        Ok(())
    }
}
