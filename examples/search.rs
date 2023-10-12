use std::collections::{HashMap, HashSet};

use cosmian_findex::{
    ChainTable, DxEnc, EntryTable, Findex, InMemoryEdx, Index, IndexedValue, Keyword, Label,
    Location,
};
use futures::executor::block_on;

fn prepare_keywords(number: i64) -> HashSet<Keyword> {
    let mut keywords = HashSet::new();
    for idx in 0..number {
        keywords.insert(Keyword::from(format!("name_{idx}").as_str()));
    }
    keywords
}

fn prepare_locations_and_words(
    number: i64,
) -> HashMap<IndexedValue<Keyword, Location>, HashSet<Keyword>> {
    let mut locations_and_words = HashMap::new();
    for idx in 0..number {
        let mut words = HashSet::new();
        words.insert(Keyword::from(format!("first_name_{idx}").as_bytes()));
        words.insert(Keyword::from(format!("name_{idx}").as_bytes()));

        locations_and_words.insert(
            IndexedValue::Data(Location::from(idx.to_be_bytes().as_slice())),
            words.clone(),
        );
    }
    locations_and_words
}

fn main() {
    let locations_and_words = prepare_locations_and_words(10000);

    //
    // Prepare indexes to be search
    //
    let mut findex = Findex::new(
        EntryTable::setup(InMemoryEdx::default()),
        ChainTable::setup(InMemoryEdx::default()),
    );

    let master_key = findex.keygen();
    let label = Label::from("label");
    block_on(findex.add(&master_key, &label, locations_and_words)).expect("msg");

    //
    // Search 1000 words
    //
    let keywords = prepare_keywords(1000);
    for _ in 0..1000 {
        block_on(
            findex.search(&master_key, &label, keywords.clone(), &|_| async {
                Ok(false)
            }),
        )
        .expect("search failed");
    }
}
