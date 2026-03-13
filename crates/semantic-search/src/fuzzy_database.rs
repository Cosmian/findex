use crate::{Error, F32Vector, VectorDB};
use cosmian_findex::IndexADT;

/// This fuzzy database uses an SSE to securely index documents under their
/// embeddings, and a secure vector database to retrieves candidates embeddings
/// to answer queries.
pub struct FuzzyDB<
    const D: usize,
    Vdb: VectorDB<Vector = F32Vector<D>>,
    Idx: IndexADT<F32Vector<D>, String>,
> {
    vdb: Vdb,
    idx: Idx,
}

impl<
    const D: usize,
    Vdb: Send + Sync + VectorDB<Vector = F32Vector<D>>,
    Idx: Send + Sync + IndexADT<F32Vector<D>, String>,
> FuzzyDB<D, Vdb, Idx>
where
    Vdb::Score: Clone,
    Error: From<<Vdb as VectorDB>::Error>
{
    pub fn new(vdb: Vdb, idx: Idx) -> Self {
        Self { vdb, idx }
    }

    pub async fn query(
        &self,
        k: usize,
        embedding: &F32Vector<D>,
    ) -> Result<Vec<(String, Vdb::Score)>, Error> {
        let candidates = self.vdb.query(k, embedding).await?;
        let mut results = Vec::with_capacity(candidates.len());
        for ((kw, _data), score) in candidates {
            let vs = self
                .idx
                .search(&kw)
                .await
                .map_err(|e| Error(e.to_string()))?;
            vs.into_iter().for_each(|v| {
                results.push((v, score.clone()));
            });
        }

        Ok(results)
    }

    pub async fn insert(&self, embedding: F32Vector<D>, metadata: Vdb::MetaData, document: String) -> Result<(), Error> {
        self.vdb.insert(embedding.clone(), metadata).await?;
        self.idx
            .insert(embedding, std::iter::once(document))
            .await
            .map_err(|e| Error(e.to_string()))
    }
}
