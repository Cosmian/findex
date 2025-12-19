//! This module provides Python bindings of a `FuzzyDB` implementation based on
//! Findex and an `IndexDB` based on SimpleLSH.

use crate::{
    Error, F32Vector, FuzzyDB, LocalitySensitiveHash, LshVectorDB, SimpleLsh, SimpleLshParameters,
    VectorDB,
    encoding::{Encoding, StringEncoder},
};
use cosmian_crypto_core::Secret;
use cosmian_findex::{Findex, KEY_LENGTH, MemoryEncryptionLayer, Op};
use cosmian_sse_memories::{ADDRESS_LENGTH, Address, PostgresMemory};
use pyo3::{exceptions::PyRuntimeError, prelude::*};
use rand::rngs::ThreadRng;
use std::collections::HashSet;
use tokio::runtime::Builder;

// The dimension of the embedding used.
const D: usize = 384;

// The dimension of the text chunks indexed.
const CHUNK_LENGTH: usize = 1024;

// The size of a f32.
const F32_LENGTH: usize = 4;

// The size of a serialized vector.
const VECTOR_LENGTH: usize = F32_LENGTH * D;

fn vector_encode<const D: usize>(
    // TODO: for now, vector databases only support insertion.
    _op: Op,
    values: HashSet<F32Vector<D>>,
) -> Result<Vec<[u8; VECTOR_LENGTH]>, Error> {
    Ok(values
        .into_iter()
        .map(|v| {
            let mut res = [0; VECTOR_LENGTH];
            for (i, e) in v.into_iter().enumerate() {
                res[1 + F32_LENGTH * i..1 + F32_LENGTH * (i + 1)].copy_from_slice(&e.to_be_bytes());
            }
            res
        })
        .collect())
}

fn vector_decode<const D: usize>(
    ws: Vec<[u8; VECTOR_LENGTH]>,
) -> Result<HashSet<F32Vector<D>>, Error> {
    ws.into_iter()
        .map(|w| {
            F32Vector::<D>::init(|i| {
                <[u8; F32_LENGTH]>::try_from(&w[F32_LENGTH * i..F32_LENGTH * (i + 1)])
                    .map_err(|e| Error(e.to_string()))
                    .map(f32::from_be_bytes)
            })
        })
        .collect()
}

type VectorSSE = Findex<
    VECTOR_LENGTH,
    F32Vector<D>,
    Error,
    MemoryEncryptionLayer<
        VECTOR_LENGTH,
        PostgresMemory<Address<ADDRESS_LENGTH>, [u8; VECTOR_LENGTH]>,
    >,
>;

type ChunkSSE = Findex<
    CHUNK_LENGTH,
    String,
    Error,
    MemoryEncryptionLayer<
        CHUNK_LENGTH,
        PostgresMemory<Address<ADDRESS_LENGTH>, [u8; CHUNK_LENGTH]>,
    >,
>;

#[pyclass]
pub struct SecureSemanticDB(FuzzyDB<D, LshVectorDB<D, SimpleLsh<D>, VectorSSE>, ChunkSSE>);

impl SecureSemanticDB {
    // This following helper method exists for the purpose of separating
    // internal from binding-related logic.

    async fn _new(
        mut key: [u8; KEY_LENGTH],
        url: String,
        table: String,
    ) -> Result<SecureSemanticDB, Error> {
        let mut rng = ThreadRng::default();
        let seed = Secret::from_unprotected_bytes(&mut key);
        let vdb = {
            let key = Secret::<KEY_LENGTH>::derive(&seed, b"1")?;
            let mem = PostgresMemory::new(url.clone(), table.clone()).await?;
            let mem = MemoryEncryptionLayer::new(&key, mem);
            let idx = Findex::new(mem, vector_encode, vector_decode);
            let lsh = SimpleLsh::init(&SimpleLshParameters { K: 20, L: 20 }, &mut rng);
            LshVectorDB::init((lsh, idx))?
        };
        let idx = {
            let key = Secret::<KEY_LENGTH>::derive(&seed, b"2")?;
            let mem = PostgresMemory::new(url, table).await?;
            let mem = MemoryEncryptionLayer::<CHUNK_LENGTH, _>::new(&key, mem);
            Findex::new(
                mem,
                StringEncoder::<CHUNK_LENGTH, CHUNK_LENGTH>::encode,
                StringEncoder::<CHUNK_LENGTH, CHUNK_LENGTH>::decode,
            )
        };
        Ok(SecureSemanticDB(FuzzyDB::new(vdb, idx)))
    }
}

#[pymethods]
impl SecureSemanticDB {
    // Pyo3's async bindings is experimental. Therefore, in each one of the
    // following methods, we instantiate a runtime in order to perform Rust
    // async calls in an asynchronous way.

    #[new]
    pub fn new(key: [u8; KEY_LENGTH], url: String, table: String) -> PyResult<Self> {
        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        rt.block_on(Self::_new(key, url, table))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    pub fn query(&self, k: usize, query: Vec<f32>) -> PyResult<Vec<(String, f32)>> {
        let query = F32Vector::<D>::try_from(&*query)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        rt.block_on(self.0.query(k, &query))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }

    pub fn insert(&self, embedding: Vec<f32>, document: String) -> PyResult<()> {
        let embedding = F32Vector::<D>::try_from(&*embedding)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        let rt = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        rt.block_on(self.0.insert(embedding, document))
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
}
