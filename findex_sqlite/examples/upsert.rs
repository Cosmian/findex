use cosmian_findex_sqlite::{upsert, utils::delete_db};
use futures::executor::block_on;

const N_ITER: usize = 10;

fn main() {
    let db = std::env::temp_dir().join("sqlite_example.db");
    for _ in 0..N_ITER {
        block_on(upsert(&db, "datasets/data.json")).expect("upsert failed");
    }
    delete_db(&db).unwrap();
}
