use std::collections::{HashMap, HashSet};

use cosmian_findex::{
    ChainTable, Data, DxEnc, EntryTable, Findex, InMemoryDb, Index, IndexedValue,
    IndexedValueToKeywordsMap, Keyword, Keywords, Label,
};
use futures::executor::block_on;

fn prepare_keywords(number: i64) -> Keywords {
    let mut keywords = HashSet::new();
    for idx in 0..number {
        keywords.insert(Keyword::from(format!("name_{idx}").as_str()));
    }
    Keywords::from(keywords)
}

fn prepare_locations_and_words(number: i64) -> IndexedValueToKeywordsMap {
    let mut locations_and_words = HashMap::new();
    for idx in 0..number {
        let mut words = HashSet::new();
        words.insert(Keyword::from(format!("first_name_{idx}").as_bytes()));
        words.insert(Keyword::from(format!("name_{idx}").as_bytes()));

        locations_and_words.insert(
            IndexedValue::Data(Data::from(idx.to_be_bytes().as_slice())),
            Keywords::from(words.clone()),
        );
    }
    IndexedValueToKeywordsMap::from(locations_and_words)
}

fn main() {
    let locations_and_words = prepare_locations_and_words(10000);

    //
    // Prepare indexes to be search
    //
    let findex = Findex::new(
        EntryTable::setup(InMemoryDb::default()),
        ChainTable::setup(InMemoryDb::default()),
    );

    let key = findex.keygen();
    let label = Label::from("label");
    block_on(findex.add(&key, &label, locations_and_words)).expect("msg");

    //
    // Search 1000 words
    //
    let keywords = prepare_keywords(1000);
    for _ in 0..1000 {
        block_on(findex.search(&key, &label, keywords.clone(), &|_| async { Ok(false) }))
            .expect("search failed");
    }
}
