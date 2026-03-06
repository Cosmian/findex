use clap::{Parser, Subcommand};
use rand::SeedableRng;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fs;
use serde_json;

use cosmian_crypto_core::{CsRng, Secret};

use cosmian_findex::{Findex, MemoryEncryptionLayer, Op};

use cosmian_sse_memories::{ADDRESS_LENGTH, Address, PostgresMemory};

use cosmian_semantic_search::{
    Error, F32Vector, FuzzyDB, LocalitySensitiveHash, LshVectorDB, SimpleLsh, SimpleLshParameters, VectorDB
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
const K: usize = 20;
const L: usize = 20;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Fixed key to retrieve values with query
    // let key = Secret::<{ cosmian_findex::KEY_LENGTH }>::random(&mut CsRng::from_entropy());

    let seed = [
        1, 0, 52, 0, 0, 0, 0, 0, 1, 0, 10, 0, 22, 32, 0, 0, 2, 0, 55, 49, 0, 11, 0, 0, 3, 0, 0, 0,
        0, 0, 2, 92,
    ];

    let key = Secret::<{ cosmian_findex::KEY_LENGTH }>::random(
        &mut <CsRng as cosmian_crypto_core::reexport::rand_core::SeedableRng>::from_seed(seed),
    );

    let findex = {
        const F32_LENGTH: usize = 4;
        const WORD_LENGTH: usize = 1 + F32_LENGTH * 384;

        fn vector_encode<const D: usize>(
            op: Op,
            values: HashSet<F32Vector<D>>,
        ) -> Result<Vec<[u8; WORD_LENGTH]>, Error> {
            Ok(values
                .into_iter()
                .map(|v| {
                    let mut res = [0; WORD_LENGTH];
                    res[0] = if op == Op::Insert { 0 } else { 1 };
                    for (i, e) in v.into_iter().enumerate() {
                        res[1 + F32_LENGTH * i..1 + F32_LENGTH * (i + 1)]
                            .copy_from_slice(&e.to_be_bytes());
                    }
                    res
                })
                .collect())
        }

        fn vector_decode<const D: usize>(
            ws: Vec<[u8; WORD_LENGTH]>,
        ) -> Result<HashSet<F32Vector<D>>, Error> {
            ws.into_iter()
                .map(|w| {
                    F32Vector::<D>::init(|i| {
                        <[u8; F32_LENGTH]>::try_from(
                            &w[1 + F32_LENGTH * i..1 + F32_LENGTH * (i + 1)],
                        )
                        .map_err(|e| Error(e.to_string()))
                        .map(f32::from_be_bytes)
                    })
                })
                .collect()
        }

        let db_url = "postgres://cosmian:cosmian@localhost/cosmian";
        let table_name = "lsh_table";

        let mem = PostgresMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::new(
            db_url.to_owned(),
            table_name.to_owned(),
        )
        .await?;

        mem.initialize().await?;

        Findex::<WORD_LENGTH, F32Vector<D>, _, _>::new(
            MemoryEncryptionLayer::new(&key, mem),
            vector_encode,
            vector_decode,
        )
    };

    // Fixed lsh tables to retrieve values with query
    // let mut rng = ThreadRng::default();
    let seed: u64 = 42;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);

    let lsh = SimpleLsh::<D>::init(&SimpleLshParameters { K, L }, &mut rng);

    let vdb = LshVectorDB::<D, _, _>::init((lsh, findex))
        .map_err(|e| anyhow::anyhow!(format!("init error: {}", e)))?;

    match cli.command {
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

            vdb.insert(fv).await?;



            println!("Success.");
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
            let results = vdb.query(k, &fv).await?;

            let results = results.into_iter().map(|(v,score)|{
                let vec = v.into_iter().collect::<Vec<f32>>();
                let score = score;
                (vec, score)
             }).collect::<Vec<(Vec<f32>, f32)>>();

            println!("{}", serde_json::to_string_pretty(&results)?);
        }
    }

    Ok(())
}
