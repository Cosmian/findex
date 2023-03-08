#[cfg(feature = "in_memory")]
use std::collections::{HashMap, HashSet};

#[cfg(feature = "in_memory")]
use cosmian_findex::Keyword;

/// Converts the given strings as a `HashSet` of Keywords.
///
/// - `keywords`    : strings to convert
#[cfg(feature = "in_memory")]
fn hashset_keywords(keywords: &[&'static str]) -> HashSet<Keyword> {
    keywords
        .iter()
        .map(|keyword| Keyword::from(*keyword))
        .collect()
}

fn main() {
    #[cfg(feature = "in_memory")]
    {
        use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
        use cosmian_findex::{
            in_memory_example::FindexInMemory, FindexUpsert, IndexedValue, KeyingMaterial, Label,
            Location,
        };
        use futures::executor::block_on;

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

        for _ in 0..100000 {
            block_on(findex.upsert(
                indexed_value_to_keywords.clone(),
                HashMap::new(),
                &master_key,
                &label,
            ))
            .unwrap();
        }
    }
}
