#[cfg(not(feature = "in_memory"))]
compile_error!("Examples require the `in_memory` feature.");

use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::CsRng;
use cosmian_findex::{
    in_memory_example::FindexInMemory, FindexSearch, FindexUpsert, IndexedValue, KeyingMaterial,
    Keyword, Label, Location,
};
use futures::executor::block_on;
use rand::SeedableRng;

fn prepare_keywords(number: i64) -> HashSet<Keyword> {
    let mut keywords = HashSet::new();
    for idx in 0..number {
        keywords.insert(Keyword::from(format!("name_{idx}").as_str()));
    }
    keywords
}

fn prepare_locations_and_words(number: i64) -> HashMap<IndexedValue, HashSet<Keyword>> {
    let mut locations_and_words = HashMap::new();
    for idx in 0..number {
        let mut words = HashSet::new();
        words.insert(Keyword::from(format!("first_name_{idx}").as_bytes()));
        words.insert(Keyword::from(format!("name_{idx}").as_bytes()));

        locations_and_words.insert(
            IndexedValue::Location(Location::from(idx.to_be_bytes().as_slice())),
            words.clone(),
        );
    }
    locations_and_words
}

fn main() {
    let mut rng = CsRng::from_entropy();
    let label = Label::random(&mut rng);
    let master_key = KeyingMaterial::new(&mut rng);

    let locations_and_words = prepare_locations_and_words(10000);

    //
    // Prepare indexes to be search
    //
    let mut findex = FindexInMemory::default();
    block_on(findex.upsert(&master_key, &label, locations_and_words, HashMap::new())).expect("msg");

    //
    // Search 1000 words
    //
    let keywords = prepare_keywords(1000);
    for _ in 0..1000 {
        block_on(findex.search(&master_key, &label, keywords.clone(), usize::MAX))
            .expect("search failed");
    }
}
