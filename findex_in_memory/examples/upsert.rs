use std::collections::{HashMap, HashSet};

use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
use cosmian_findex::{FindexUpsert, IndexedValue, KeyingMaterial, Keyword, Label, Location};
use cosmian_findex_in_memory::FindexInMemory;
use futures::executor::block_on;

const N_ITER: usize = 100;

/// Converts the given strings as a `HashSet` of Keywords.
///
/// - `keywords`    : strings to convert
fn hashset_keywords(keywords: &[&'static str]) -> HashSet<Keyword> {
    keywords
        .iter()
        .map(|keyword| Keyword::from(*keyword))
        .collect()
}

fn main() {
    let mut rng = CsRng::from_entropy();
    let label = Label::random(&mut rng);
    let master_key = KeyingMaterial::new(&mut rng);

    let mut indexed_value_to_keywords = HashMap::new();

    // direct location robert doe
    let robert_doe_location = Location::from("robert doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Location(robert_doe_location),
        hashset_keywords(&["robert", "doe"]),
    );

    // direct location john doe
    let john_doe_location = Location::from("john doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Location(john_doe_location),
        hashset_keywords(&["john", "doe"]),
    );

    // direct location for rob...
    let rob_location = Location::from("rob DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Location(rob_location),
        hashset_keywords(&["rob"]),
    );
    // ... and indirection to robert
    indexed_value_to_keywords.insert(
        IndexedValue::NextKeyword(Keyword::from("robert")),
        hashset_keywords(&["rob"]),
    );

    let mut findex = FindexInMemory::default();

    for _ in 0..N_ITER {
        block_on(findex.upsert(indexed_value_to_keywords.clone(), &master_key, &label)).unwrap();
    }
}
