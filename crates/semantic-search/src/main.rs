use core::hash::Hash;
use std::{collections::HashSet, convert::TryFrom, fs};

use clap::{Parser, Subcommand};
use cosmian_crypto_core::{CsRng, Secret, bytes_ser_de::Serializable};
use cosmian_findex::{Findex, MemoryEncryptionLayer, Op, generic_decode, generic_encode};
use cosmian_semantic_search::{
    Error, F32Vector, FalconLsh, FalconLshParameters, LocalitySensitiveHash, SimpleLsh,
    SimpleLshParameters, VDBParameters, Vdb, VectorDB,
};
use cosmian_sse_memories::{ADDRESS_LENGTH, Address, PostgresMemory};
use rand::SeedableRng;
use serde_json::{self};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the database (e.g. create tables). Should be run before any
    /// other command.
    Init,

    /// Drop the database (e.g. drop tables). Use with caution.
    Drop,

    /// Insert a vector (JSON array) with an identifier
    Insert {
        #[arg(long)]
        data: String,
        /// JSON array, e.g. '[0.1, 0.2, ...]'
        #[arg(long)]
        vector: Option<String>,
        /// Path to a file containing a JSON array. Preferred for large vectors.
        #[arg(long)]
        vector_file: Option<String>,
    },

    /// Query the DB with a vector (JSON array). Prints JSON results.
    Query {
        /// JSON array
        #[arg(long)]
        vector: Option<String>,
        /// Path to a file containing a JSON array.
        #[arg(long)]
        vector_file: Option<String>,
        /// Number of results
        #[arg(long, default_value_t = 10)]
        k: usize,
    },
}

const D: usize = 384;
const K: usize = 5;
const L: usize = 5;
const IPROBE: Option<usize> = Some(3);
const QPROBE: Option<usize> = Some(5);

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Fixed key to retrieve values with query
    // let key = Secret::<{ cosmian_findex::KEY_LENGTH }>::random(&mut
    // CsRng::from_entropy());

    let seed = [
        0, 0, 52, 0, 0, 0, 0, 0, 1, 0, 10, 0, 22, 32, 0, 0, 2, 0, 55, 49, 0, 11, 0, 0, 3, 0, 0, 0,
        0, 0, 2, 92,
    ];

    let key = Secret::<{ cosmian_findex::KEY_LENGTH }>::random(
        &mut <CsRng as cosmian_crypto_core::reexport::rand_core::SeedableRng>::from_seed(seed),
    );

    let findex = {
        const F32_LENGTH: usize = 4;
        const WORD_LENGTH: usize = 1 + F32_LENGTH * 384 + 513;

        fn encode<const D: usize, T: Hash + Eq + Serializable>(
            op: Op,
            values: HashSet<(F32Vector<D>, T)>,
        ) -> Result<Vec<[u8; WORD_LENGTH]>, Error> {
            let bytes = values
                .serialize()
                .map_err(|e| Error(e.to_string()))?
                .to_vec();

            generic_encode::<WORD_LENGTH, _>(op, HashSet::from_iter([bytes]))
                .map_err(|e| Error(e.to_string()))
        }

        fn decode<const D: usize, T: Hash + Eq + Serializable>(
            ws: Vec<[u8; WORD_LENGTH]>,
        ) -> Result<HashSet<(F32Vector<D>, T)>, Error> {
            let bytes = generic_decode::<WORD_LENGTH, _, Vec<u8>>(ws).map_err(|e| Error(e))?;
            bytes
                .into_iter()
                .map(|bytes| <HashSet<(F32Vector<D>, T)>>::deserialize(&bytes))
                .try_fold(HashSet::new(), |mut a, e| {
                    e.map(|set| {
                        set.into_iter().for_each(|b| {
                            a.insert(b);
                            ()
                        });
                        a
                    })
                    .map_err(|e| Error(e.to_string()))
                })
        }

        let db_url = "postgres://cosmian:cosmian@localhost/cosmian";
        let table_name = "lsh_table";

        let mem = PostgresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::new(
            db_url.to_owned(),
            table_name.to_owned(),
        )
        .await?;

        mem.initialize().await?;

        Findex::<WORD_LENGTH, _, _, _>::new(
            MemoryEncryptionLayer::new(&key, mem),
            encode::<D, String>,
            decode,
        )
    };

    // Fixed lsh tables to retrieve values with query
    // let mut rng = ThreadRng::default();
    let seed: u64 = 42;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let lsh = FalconLsh::<D>::init(&FalconLshParameters { K, L }, &mut rng);

    let vdb_falcon = Vdb::<D, _, _>::init(VDBParameters {
        lsh,
        index: findex.clone(),
        iprobe: IPROBE,
        qprobe: QPROBE,
    })
    .map_err(|e| anyhow::anyhow!(format!("init error: {}", e)))?;

    let lsh = SimpleLsh::<D>::init(&SimpleLshParameters { K, L }, &mut rng);

    let vdb_simplelsh = Vdb::<D, _, _>::init(VDBParameters {
        lsh,
        index: findex,
        iprobe: None,
        qprobe: None,
    })
    .map_err(|e| anyhow::anyhow!(format!("init error: {}", e)))?;

    match cli.command {
        Commands::Init => {
            //TODO: implement init command to initialize the database
        }
        Commands::Drop => {
            //TODO: implement drop command to clear the database
        }
        Commands::Insert {
            data,
            vector,
            vector_file,
        } => {
            let v: Vec<f32> = if let Some(file) = vector_file {
                let s = fs::read_to_string(file)?;
                serde_json::from_str(&s)
                    .map_err(|e| anyhow::anyhow!(format!("vector parse error: {}", e)))?
            } else if let Some(s) = vector {
                serde_json::from_str(&s)
                    .map_err(|e| anyhow::anyhow!(format!("vector parse error: {}", e)))?
            } else {
                return Err(anyhow::anyhow!("missing --vector or --vector-file"));
            };
            if v.len() != D {
                return Err(anyhow::anyhow!(format!("vector length must be {}", D)));
            }
            let fv = F32Vector::<D>::try_from(v.as_slice())?;
            //TODO: use the FuzzDB to insert an entire source
            vdb_falcon.insert(fv.clone(), data.clone()).await?;
            vdb_simplelsh.insert(fv.clone(), data.clone()).await?;
        }

        Commands::Query {
            vector,
            vector_file,
            k,
        } => {
            let v: Vec<f32> = if let Some(file) = vector_file {
                let s = fs::read_to_string(file)?;
                serde_json::from_str(&s)
                    .map_err(|e| anyhow::anyhow!(format!("vector parse error: {}", e)))?
            } else if let Some(s) = vector {
                serde_json::from_str(&s)
                    .map_err(|e| anyhow::anyhow!(format!("vector parse error: {}", e)))?
            } else {
                return Err(anyhow::anyhow!("missing --vector or --vector-file"));
            };
            if v.len() != D {
                return Err(anyhow::anyhow!(format!("vector length must be {}", D)));
            }
            let fv = F32Vector::<D>::try_from(v.as_slice())?;

            let results = vdb_falcon.query(k, &fv).await?;

            let results = results
                .into_iter()
                .map(|((vec, data), score)| {
                    let vec = vec.into_iter().collect::<Vec<f32>>();
                    let score = score;
                    (vec, data, score)
                })
                .collect::<Vec<(Vec<f32>, String, f32)>>();

            let results2 = vdb_simplelsh.query(k, &fv).await?;

            let results2 = results2
                .into_iter()
                .map(|((vec, data), score)| {
                    let vec = vec.into_iter().collect::<Vec<f32>>();
                    let score = score;
                    (vec, data, score)
                })
                .collect::<Vec<(Vec<f32>, String, f32)>>();

            let results = vec![results, results2];

            println!("{}", serde_json::to_string_pretty(&results)?);
        }
    }

    Ok(())
}
