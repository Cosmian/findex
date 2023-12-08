use std::collections::HashMap;

use cosmian_findex::{
    ChainTable, Data, DxEnc, EntryTable, Findex, InMemoryDb, Index, IndexedValue,
    IndexedValueToKeywordsMap, Keyword, Keywords, Label,
};
use futures::executor::block_on;

fn main() {
    let mut indexed_value_to_keywords = HashMap::new();

    // direct location robert doe
    let robert_doe_location = Data::from("robert doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Data(robert_doe_location),
        Keywords::from_iter(["robert", "doe"]),
    );

    // direct location john doe
    let john_doe_location = Data::from("john doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Data(john_doe_location),
        Keywords::from_iter(["john", "doe"]),
    );

    // direct location for rob...
    let rob_location = Data::from("rob DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Data(rob_location),
        Keywords::from_iter(["rob"]),
    );
    // ... and indirection to robert
    indexed_value_to_keywords.insert(
        IndexedValue::Pointer(Keyword::from("robert")),
        Keywords::from_iter(["rob"]),
    );

    let findex = Findex::new(
        EntryTable::setup(InMemoryDb::default()),
        ChainTable::setup(InMemoryDb::default()),
    );

    let key = findex.keygen();
    let label = Label::from("label");

    for _ in 0..1_000_000 {
        block_on(findex.add(
            &key,
            &label,
            IndexedValueToKeywordsMap::from(indexed_value_to_keywords.clone()),
        ))
        .unwrap();
    }
}
