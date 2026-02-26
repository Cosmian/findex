use clap::{Parser, Subcommand};
use futures::executor::block_on;
use rand::rngs::ThreadRng;
use std::convert::TryFrom;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use cosmian_semantic_search::{
    SimpleLsh, SimpleLshParameters, F32Vector, LshVectorDB, FuzzyDB,
    cleartext_index::CleartextIndex,
};
use cosmian_semantic_search::{LocalitySensitiveHash, VectorDB};

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

const STORE_FILE: &str = "store.json";

const D: usize = 384;
const K: usize = 20;
const L: usize = 20;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // load persisted data -> vector store (JSON)
    let mut store: HashMap<String, Vec<f32>> = if Path::new(STORE_FILE).exists() {
        let s = fs::read_to_string(STORE_FILE)?;
        serde_json::from_str(&s)?
    } else {
        HashMap::new()
    };

    // build LSH + CleartextIndex (for vdb) and CleartextIndex (for embedding->data)
    let mut rng = ThreadRng::default();
    let lsh = SimpleLsh::<D>::init(&SimpleLshParameters { K, L }, &mut rng);
    let index_for_vdb = CleartextIndex::<(u64, u64), F32Vector<D>>::default();
    let vdb = LshVectorDB::<D, _, _>::init((lsh, index_for_vdb))
        .map_err(|e| anyhow::anyhow!(format!("init error: {}", e)))?;

    let index_for_docs = CleartextIndex::<F32Vector<D>, String>::default();
    let fuzzy = FuzzyDB::new(vdb, index_for_docs);

    // rebuild index from persisted store via FuzzyDB
    for (data, vec) in store.clone() {
        if vec.len() != D {
            continue;
        }
        let fv = F32Vector::<D>::try_from(vec.as_slice())?;
        block_on(fuzzy.insert(fv, data)).map_err(|e| anyhow::anyhow!(format!("insert error: {}", e)))?;
    }

    match cli.command {
        Commands::Insert { data, vector, vector_file } => {
            let v: Vec<f32> = if let Some(file) = vector_file {
                let s = fs::read_to_string(file)?;
                serde_json::from_str(&s).map_err(|e| anyhow::anyhow!(format!("vector parse error: {}", e)))?
            } else if let Some(s) = vector {
                serde_json::from_str(&s).map_err(|e| anyhow::anyhow!(format!("vector parse error: {}", e)))?
            } else {
                return Err(anyhow::anyhow!("missing --vector or --vector-file"));
            };
            if v.len() != D {
                return Err(anyhow::anyhow!(format!("vector length must be {}", D)));
            }
            let fv = F32Vector::<D>::try_from(v.as_slice())?;
            block_on(fuzzy.insert(fv, data.clone())).map_err(|e| anyhow::anyhow!(format!("insert error: {}", e)))?;
            // persist mapping data -> vector (JSON for Python interop)
            store.insert(data.clone(), v);
            fs::write(STORE_FILE, serde_json::to_string_pretty(&store)?)?;
            println!("Inserted data '{}'.", data);
        }

        Commands::Query { vector, vector_file, k } => {
            let v: Vec<f32> = if let Some(file) = vector_file {
                let s = fs::read_to_string(file)?;
                serde_json::from_str(&s).map_err(|e| anyhow::anyhow!(format!("vector parse error: {}", e)))?
            } else if let Some(s) = vector {
                serde_json::from_str(&s).map_err(|e| anyhow::anyhow!(format!("vector parse error: {}", e)))?
            } else {
                return Err(anyhow::anyhow!("missing --vector or --vector-file"));
            };
            if v.len() != D {
                return Err(anyhow::anyhow!(format!("vector length must be {}", D)));
            }
            let fv = F32Vector::<D>::try_from(v.as_slice())?;
            let results = block_on(fuzzy.query(k, &fv)).map_err(|e| anyhow::anyhow!(format!("query error: {}", e)))?;
            let mut out = Vec::new();
            for (doc_id, score) in results {
                out.push(serde_json::json!({"data": doc_id, "score": score}));
            }

            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }

    Ok(())
}
