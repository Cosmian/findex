use cosmian_crypto_core::CsRng;
use cosmian_findex::{mm, set, Data, InMemoryDb, Index, Keyword, Mm, Set, UserKey};
use futures::executor::block_on;
use rand::SeedableRng;

fn prepare_keywords(number: i64) -> Set<Keyword> {
    let mut keywords = set!();
    for idx in 0..number {
        keywords.insert(Keyword::from(format!("name_{idx}").as_str()));
    }
    keywords
}

fn prepare_locations_and_words(number: i64) -> Mm<Keyword, Data> {
    let mut index = mm!();
    for idx in 0..number {
        index.insert(
            format!("first_name_{idx}").as_bytes().to_vec().into(),
            vec![idx.to_be_bytes().to_vec().into()],
        );
        index.insert(
            format!("name_{idx}").as_bytes().to_vec().into(),
            vec![idx.to_be_bytes().to_vec().into()],
        );
    }
    index
}

fn main() {
    let locations_and_words = prepare_locations_and_words(10000);

    //
    // Prepare indexes to be search
    //
    let mut rng = CsRng::from_entropy();
    let key = UserKey::random(&mut rng);
    let entry_table = InMemoryDb::default();
    let chain_table = InMemoryDb::default();

    let index = Index::new(&key, entry_table, chain_table).unwrap();

    block_on(index.add(locations_and_words)).unwrap();

    //
    // Search 1000 words
    //
    let keywords = prepare_keywords(1000);
    for _ in 0..1000 {
        block_on(index.search::<_, Data>(keywords.clone())).expect("search failed");
    }
}
