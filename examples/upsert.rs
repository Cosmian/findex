use cosmian_crypto_core::CsRng;
use cosmian_findex::{mm, Data, InMemoryDb, Index, Keyword, UserKey};
use futures::executor::block_on;
use rand::SeedableRng;

fn main() {
    let robert_doe_location = Data::from("robert doe DB location");
    let john_doe_location = Data::from("john doe DB location");
    let rob_location = Data::from("rob DB location");

    let indexed_value_to_keywords = mm!(
        (
            Keyword::from("doe"),
            vec![robert_doe_location.clone(), john_doe_location.clone()],
        ),
        (Keyword::from("john"), vec![john_doe_location],),
        (Keyword::from("robert"), vec![robert_doe_location],),
        (Keyword::from("rob"), vec![rob_location]),
    );

    let mut rng = CsRng::from_entropy();
    let key = UserKey::random(&mut rng);
    let entry_table = InMemoryDb::default();
    let chain_table = InMemoryDb::default();

    let index = Index::new(&key, entry_table, chain_table).unwrap();

    for _ in 0..1_000_000 {
        block_on(index.add(indexed_value_to_keywords.clone())).unwrap();
    }
}
