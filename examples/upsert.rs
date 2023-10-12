use std::collections::{HashMap, HashSet};

use cosmian_findex::{
    ChainTable, DxEnc, EntryTable, Findex, InMemoryEdx, Index, IndexedValue, Keyword, Label,
    Location,
};
use futures::executor::block_on;

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
    let mut indexed_value_to_keywords = HashMap::new();

    // direct location robert doe
    let robert_doe_location = Location::from("robert doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Data(robert_doe_location),
        hashset_keywords(&["robert", "doe"]),
    );

    // direct location john doe
    let john_doe_location = Location::from("john doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Data(john_doe_location),
        hashset_keywords(&["john", "doe"]),
    );

    // direct location for rob...
    let rob_location = Location::from("rob DB location");
    indexed_value_to_keywords.insert(IndexedValue::Data(rob_location), hashset_keywords(&["rob"]));
    // ... and indirection to robert
    indexed_value_to_keywords.insert(
        IndexedValue::Pointer(Keyword::from("robert")),
        hashset_keywords(&["rob"]),
    );

    let findex = Findex::new(
        EntryTable::setup(InMemoryEdx::default()),
        ChainTable::setup(InMemoryEdx::default()),
    );

    let master_key = findex.keygen();
    let label = Label::from("label");

    for _ in 0..1_000_000 {
        block_on(findex.add(&master_key, &label, indexed_value_to_keywords.clone())).unwrap();
    }
}
