use crate::{Error, F32Vector, LocalitySensitiveHash, VectorDB};
use cosmian_findex::IndexADT;
use std::{collections::HashSet, hash::Hash, pin::Pin, future::Future, marker::PhantomData};

/// Implementation of a vector DB based on an LSH scheme and an index.
///
/// The LSH is instantiated K times, but a single index is used. The LSH tables
/// are therefore virtual tables: their ID is used in the key and is akin to a
/// domain-separation parameter.
///
/// If the underlying LSH scheme returns multiple probes, those probes are used
/// in a symmetric way for both inserting to and searching from the DB.
pub struct LshVectorDB<const D: usize, Lsh, Index, Data>
    where
        Lsh: LocalitySensitiveHash<Input = F32Vector<D>>,
        Lsh::Output: Send + Sync + Clone + Eq + Hash,
        Index: IndexADT<Lsh::Output, (Lsh::Input, Option<Data>)>,
        Data: Clone + Send + Sync + Eq + Hash,
    {
        lsh: Lsh,
        index: Index,
        _marker: PhantomData<Data>,
    }

    impl<const D: usize, Lsh, Index, Data> VectorDB for LshVectorDB<D, Lsh, Index, Data>
    where
        Lsh: Send + Sync + LocalitySensitiveHash<Input = F32Vector<D>>,
        Lsh::Output: Send + Sync + Clone + Eq + Hash,
        Index: Send + Sync + IndexADT<Lsh::Output, (Lsh::Input, Option<Data>)>,
        Data: Clone + Send + Sync + Eq + Hash,
    {
        type Parameters = (Lsh, Index);
        type Vector = Lsh::Input;
        type Data = Data;
        type Score = f32;
        type Error = Error;

        fn init(params: Self::Parameters) -> Result<Self, Self::Error> {
            Ok(Self {
                lsh: params.0,
                index: params.1,
            })
        }

        fn query<'a>(
            &'a self,
            k: usize,
            query: &'a Self::Vector,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<(Self::Vector, Option<Self::Data>, Self::Score)>, Self::Error>> + Send + 'a>> {
            Box::pin(async move {
                let mut candidates = HashSet::new();
                for probe in self.lsh.hash(query) {
                    let new_candidates = self.index.search(&probe).await.map_err(|e| Error(format!("index error: {e}")))?;
                    for c in new_candidates {
                        candidates.insert(c);
                    }
                }
                Ok(query.mips_with_optional_data(k, candidates))
            })
        }

        fn insert<'a>(
            &'a self,
            point: Self::Vector,
            data: Option<Self::Data>,
        ) -> Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send + 'a>> {
            Box::pin(async move {
                for probe in self.lsh.hash(&point) {
                    let values = std::iter::once((point.clone(), data.clone())).collect::<HashSet<_>>();
                    self.index.insert(probe, values).await.map_err(|e| Error(format!("index error: {e}")))?;
                }
                Ok(())
            })
        }
    }