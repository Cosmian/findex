use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader},
    result::Result,
    sync::Arc,
};

use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
use cosmian_findex::{
    ChainTable, DxEnc, EntryTable, Error, Findex, InMemoryEdx, Index, IndexedValue,
    IndexedValueToKeywordsMap, Keyword, Keywords, KvStoreError, Label, Location,
};
use futures::executor::block_on;
use rand::Rng;

const MIN_KEYWORD_LENGTH: usize = 3;

/// Computes the index graph of the given `Keyword`.
///
/// - `keyword`             : `Keyword` of which to compute the index graph
/// - `min_keyword_length`  : number of letters to use as graph root
fn compute_index_graph(
    keyword: &Keyword,
    min_keyword_length: usize,
) -> HashMap<IndexedValue<Keyword, Location>, HashSet<Keyword>> {
    if keyword.len() <= min_keyword_length {
        return HashMap::new();
    }
    let mut res = HashMap::with_capacity(keyword.len() - min_keyword_length);
    for i in min_keyword_length..keyword.len() {
        let indexing_keyword = Keyword::from(&keyword[..i]);
        let indexed_value = IndexedValue::Pointer(Keyword::from(&keyword[..=i]));
        res.insert(indexed_value, HashSet::from_iter([indexing_keyword]));
    }
    res
}

/// Adds the graph of the given `Keyword` to the given `IndexedValue` to
/// `Keyword`s map.
///
/// - `keyword`             : `Keyword` to upsert as graph
/// - `min_keyword_length`  : number of letters to use as graph root
/// - `map`                 : `IndexedValue` to `Keyword`s map
fn add_keyword_graph(
    keyword: &Keyword,
    min_keyword_length: usize,
    map: &mut HashMap<IndexedValue<Keyword, Location>, Keywords>,
) {
    let graph = compute_index_graph(keyword, min_keyword_length);
    for (key, values) in graph {
        let entry = map.entry(key).or_default();
        for value in values {
            entry.insert(value);
        }
    }
}

/// Check the given keyword has a match in the given search results, and
/// that this match is equal to the given `indexed_value`.
fn check_search_result(
    search_results: &HashMap<Keyword, HashSet<Location>>,
    keyword: &Keyword,
    location: &Location,
) -> Result<(), String> {
    let results = search_results.get(keyword).ok_or_else(|| {
        format!(
            "keyword '{}' is not present in the given set",
            String::from_utf8(keyword.to_vec()).unwrap()
        )
    })?;
    if results.contains(location) {
        Ok(())
    } else {
        Err(format!("{location:?} not found for keyword {keyword:?}"))
    }
}

/// Checks the `progress` callback works.
///
/// The results returned by the callback for a "rob" search should contain
/// either:
/// - a pointer to the "robert" keyword as result for the "rob" keyword
/// - the Location associated to "robert" as result for the "robert" keyword.
///
/// No further search should be performed after finding the Robert's location.
/// Hence the location associated to the keyword "roberta" should not be
/// returned by `search`.
#[actix_rt::test]
async fn test_progress_callback() -> Result<(), Error<KvStoreError>> {
    let mut indexed_value_to_keywords = HashMap::new();

    let robert_doe_location = Location::from("Robert Doe's location");
    let roberta_location = Location::from("Roberta's location");
    let rob_location = Location::from("Rob's location");
    let robert_keyword = Keyword::from("robert");
    let rob_keyword = Keyword::from("rob");
    let roberta_keyword = Keyword::from("roberta");

    // Index locations.
    indexed_value_to_keywords.insert(
        IndexedValue::Data(robert_doe_location.clone()),
        Keywords::from_iter(["robert", "doe"]),
    );
    indexed_value_to_keywords.insert(
        IndexedValue::Data(rob_location.clone()),
        Keywords::from_iter(["rob"]),
    );
    indexed_value_to_keywords.insert(
        IndexedValue::Data(roberta_location.clone()),
        Keywords::from_iter(["robert"]),
    );

    // Index indirections.
    indexed_value_to_keywords.insert(
        IndexedValue::Pointer(robert_keyword.clone()),
        Keywords::from_iter(["rob"]),
    );
    indexed_value_to_keywords.insert(
        IndexedValue::Pointer(roberta_keyword),
        Keywords::from_iter(["robert"]),
    );

    let findex = Findex::new(
        EntryTable::setup(InMemoryEdx::default()),
        ChainTable::setup(InMemoryEdx::default()),
    );

    let master_key = findex.keygen();
    let label = Label::from("First label.");

    findex
        .add(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from(indexed_value_to_keywords),
        )
        .await?;

    async fn user_interrupt(
        local_results: HashMap<Keyword, HashSet<IndexedValue<Keyword, Location>>>,
    ) -> Result<bool, String> {
        let mut is_correct = false;
        let mut is_last = false;

        for (key, values) in local_results {
            if key == Keyword::from("robert")
                && values.contains(&IndexedValue::Data(Location::from("Robert Doe's location")))
            {
                println!("here");
                is_last = true;
                is_correct = true;
            } else if key == Keyword::from("rob")
                && values.contains(&IndexedValue::Pointer(Keyword::from("robert")))
            {
                is_correct = true;
            }
        }

        Ok(is_last && !is_correct)
    }

    let rob_search = findex
        .search(
            &master_key,
            &label,
            Keywords::from_iter([rob_keyword.clone()]),
            &user_interrupt,
        )
        .await?;

    check_search_result(&rob_search, &rob_keyword, &robert_doe_location).unwrap();
    check_search_result(&rob_search, &rob_keyword, &rob_location).unwrap();
    assert!(rob_search
        .get(&rob_keyword)
        .unwrap()
        .contains(&roberta_location));

    Ok(())
}

#[actix_rt::test]
async fn test_deletions() -> Result<(), Error<KvStoreError>> {
    let findex = Findex::new(
        EntryTable::setup(InMemoryEdx::default()),
        ChainTable::setup(InMemoryEdx::default()),
    );

    let master_key = findex.keygen();
    let label = Label::from("First label.");

    // Delete no keyword.
    let res = findex
        .delete(&master_key, &label, IndexedValueToKeywordsMap::default())
        .await
        .unwrap();
    assert_eq!(res, Keywords::default());

    // Indexed a location for a keyword.
    let res = findex
        .add(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from([(
                IndexedValue::Data(Location::from("location")),
                Keywords::from_iter([Keyword::from("keyword")]),
            )]),
        )
        .await
        .unwrap();
    assert_eq!(res, Keywords::from_iter([Keyword::from("keyword")]));

    // Indexed another location for this keyword.
    let res = findex
        .delete(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from([(
                IndexedValue::Data(Location::from("another location")),
                Keywords::from_iter([Keyword::from("keyword")]),
            )]),
        )
        .await
        .unwrap();
    assert_eq!(res, Keywords::default());

    // Indexed this location for another keyword.
    let res = findex
        .delete(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from([(
                IndexedValue::Data(Location::from("location")),
                Keywords::from_iter([Keyword::from("another keyword")]),
            )]),
        )
        .await
        .unwrap();
    assert_eq!(res, Keywords::from_iter([Keyword::from("another keyword")]));

    // Indexed this location for this keyword.
    let res = findex
        .delete(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from([(
                IndexedValue::Data(Location::from("location")),
                Keywords::from_iter([Keyword::from("keyword")]),
            )]),
        )
        .await
        .unwrap();
    assert_eq!(res, Keywords::default());

    // Nothing is indexed.
    let res = findex
        .search(
            &master_key,
            &label,
            Keywords::from_iter([
                Keyword::from("keyword"),
                Keyword::from("another keyword"),
                Keyword::from("keyword not indexed"),
            ]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();

    assert_eq!(
        res.get(&Keyword::from("keyword")),
        Some(HashSet::new()).as_ref()
    );

    assert_eq!(
        res.get(&Keyword::from("another keyword")),
        Some(HashSet::new()).as_ref()
    );

    // There is no difference between a keyword indexed and not indexed.
    assert_eq!(
        res.get(&Keyword::from("keyword not indexed")),
        Some(HashSet::new()).as_ref()
    );

    assert_eq!(res.get(&Keyword::from("keyword not searched")), None);

    Ok(())
}

#[actix_rt::test]
async fn test_double_add() -> Result<(), Error<KvStoreError>> {
    let findex = Findex::new(
        EntryTable::setup(InMemoryEdx::default()),
        ChainTable::setup(InMemoryEdx::default()),
    );

    let master_key = findex.keygen();
    let label = Label::from("First label.");

    // Indexed a first location for the single keyword.
    let res = findex
        .add(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from([(
                IndexedValue::Data(Location::from("first location")),
                Keywords::from_iter([Keyword::from("single keyword")]),
            )]),
        )
        .await
        .unwrap();
    assert_eq!(res, Keywords::from_iter([Keyword::from("single keyword")]));

    // Indexed a second location for the single keyword.
    let res = findex
        .add(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from([(
                IndexedValue::Data(Location::from("second location")),
                Keywords::from_iter([Keyword::from("single keyword")]),
            )]),
        )
        .await
        .unwrap();
    assert_eq!(res, Keywords::default());
    Ok(())
}

#[actix_rt::test]
async fn test_findex() -> Result<(), Error<KvStoreError>> {
    let mut rng = CsRng::from_entropy();

    let mut removed_items: HashSet<Location> = HashSet::new();

    let robert_keyword = Keyword::from("robert");
    let rob_keyword = Keyword::from("rob");
    let doe_keyword = Keyword::from("doe");

    let mut indexed_value_to_keywords = HashMap::new();

    // direct location robert doe
    let robert_doe_location = Location::from("robert doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Data(robert_doe_location.clone()),
        Keywords::from_iter(["robert", "doe"]),
    );

    // direct location john doe
    let john_doe_location = Location::from("john doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Data(john_doe_location.clone()),
        Keywords::from_iter(["john", "doe"]),
    );

    // direct location for rob...
    let rob_location = Location::from("rob DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Data(rob_location.clone()),
        Keywords::from_iter(["rob"]),
    );
    // ... and indirection to robert
    indexed_value_to_keywords.insert(
        IndexedValue::Pointer(robert_keyword.clone()),
        Keywords::from_iter(["rob"]),
    );

    let findex = Findex::new(
        EntryTable::setup(InMemoryEdx::default()),
        ChainTable::setup(InMemoryEdx::default()),
    );

    let master_key = findex.keygen();
    let label = Label::from("First label.");

    findex
        .add(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from(indexed_value_to_keywords),
        )
        .await
        .unwrap();

    // search robert
    let robert_search = findex
        .search(
            &master_key,
            &label,
            Keywords::from_iter([robert_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    check_search_result(&robert_search, &robert_keyword, &robert_doe_location).unwrap();

    // cannot find robert with wrong label
    let robert_search = findex
        .search(
            &master_key,
            &Label::random(&mut rng),
            Keywords::from_iter([robert_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    assert_eq!(robert_search.get(&robert_keyword), Some(&HashSet::new()));

    // search doe
    let doe_search = findex
        .search(
            &master_key,
            &label,
            Keywords::from_iter([doe_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    check_search_result(&doe_search, &doe_keyword, &robert_doe_location).unwrap();
    check_search_result(&doe_search, &doe_keyword, &john_doe_location).unwrap();

    // search rob without graph search
    let rob_search = findex
        .search(
            &master_key,
            &label,
            Keywords::from_iter([rob_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    check_search_result(&rob_search, &rob_keyword, &rob_location).unwrap();

    // search rob with graph search
    let rob_search = findex
        .search(
            &master_key,
            &label,
            Keywords::from_iter([rob_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    check_search_result(&rob_search, &rob_keyword, &robert_doe_location).unwrap();
    check_search_result(&rob_search, &rob_keyword, &rob_location).unwrap();

    //
    // Add Jane Doe to indexes
    //

    let jane_keyword = Keyword::from("jane");
    let mut indexed_value_to_keywords = HashMap::new();
    let jane_doe_location = Location::from("jane doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Data(jane_doe_location.clone()),
        Keywords::from_iter(["jane", "doe"]),
    );
    findex
        .add(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from(indexed_value_to_keywords),
        )
        .await
        .unwrap();

    // search jane
    let jane_search = findex
        .search(
            &master_key,
            &label,
            Keywords::from_iter([jane_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    check_search_result(&jane_search, &jane_keyword, &jane_doe_location).unwrap();

    // search robert (no change)
    let robert_search = findex
        .search(
            &master_key,
            &label,
            Keywords::from_iter([robert_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    check_search_result(&robert_search, &robert_keyword, &robert_doe_location).unwrap();

    // search doe (jane added)
    let doe_search = findex
        .search(
            &master_key,
            &label,
            Keywords::from_iter([doe_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    assert_eq!(
        doe_search
            .get(&doe_keyword)
            .map(std::collections::HashSet::len)
            .unwrap_or_default(),
        3
    );
    check_search_result(&doe_search, &doe_keyword, &jane_doe_location).unwrap();
    check_search_result(&doe_search, &doe_keyword, &robert_doe_location).unwrap();
    check_search_result(&doe_search, &doe_keyword, &john_doe_location).unwrap();

    // search rob (no change)
    let rob_search = findex
        .search(
            &master_key,
            &label,
            Keywords::from_iter([rob_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    check_search_result(&rob_search, &rob_keyword, &rob_location).unwrap();

    let mut old_master_key;
    let mut old_label;
    let mut new_label = label;
    let mut new_master_key = master_key;

    // If nothing is removed, a lot of small compact should not affect the
    // search results
    for i in 1..=100 {
        println!("Compacting {i}/100");
        old_master_key = new_master_key;
        old_label = new_label;
        new_label = Label::random(&mut rng);
        new_master_key = findex.keygen();
        findex
            .compact(
                &old_master_key,
                &new_master_key,
                &old_label,
                &new_label,
                i,
                &|indexed_data| async {
                    Ok(indexed_data
                        .into_iter()
                        .filter(|data| !removed_items.contains(data))
                        .collect())
                },
            )
            .await
            .unwrap();

        let doe_search = findex
            .search(
                &new_master_key,
                &new_label,
                Keywords::from_iter([doe_keyword.clone()]),
                &|_| async { Ok(false) },
            )
            .await
            .unwrap();
        check_search_result(&doe_search, &doe_keyword, &robert_doe_location).unwrap();
        check_search_result(&doe_search, &doe_keyword, &john_doe_location).unwrap();
        check_search_result(&doe_search, &doe_keyword, &jane_doe_location).unwrap();
    }

    // Remove the location "Jane Doe" from the DB. The next compact operation should
    // remove it from the index.
    removed_items.insert(jane_doe_location);

    old_master_key = new_master_key;
    new_master_key = findex.keygen();
    old_label = new_label;
    new_label = Label::random(&mut rng);
    findex
        .compact(
            &old_master_key,
            &new_master_key,
            &old_label,
            &new_label,
            1,
            &|indexed_data| async {
                Ok(indexed_data
                    .into_iter()
                    .filter(|data| !removed_items.contains(data))
                    .collect())
            },
        )
        .await
        .unwrap();

    // search jane
    let jane_search = findex
        .search(
            &new_master_key,
            &new_label,
            Keywords::from_iter([jane_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();

    // Jane is not indexed anymore.
    assert_eq!(jane_search.get(&jane_keyword), Some(&HashSet::new()));

    // search doe (jane removed)
    let doe_search = findex
        .search(
            &new_master_key,
            &new_label,
            Keywords::from_iter([doe_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    check_search_result(&doe_search, &doe_keyword, &robert_doe_location).unwrap();
    check_search_result(&doe_search, &doe_keyword, &john_doe_location).unwrap();

    // Cannot search doe with the old label
    let doe_search = findex
        .search(
            &new_master_key,
            &old_label,
            Keywords::from_iter([doe_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    assert_eq!(doe_search.get(&doe_keyword), Some(&HashSet::new()));

    for i in 1..=100 {
        println!("Compacting {i}/100");
        old_master_key = new_master_key;
        new_master_key = findex.keygen();
        old_label = new_label;
        new_label = Label::random(&mut rng);
        findex
            .compact(
                &old_master_key,
                &new_master_key,
                &old_label,
                &new_label,
                i,
                &|indexed_data| async {
                    Ok(indexed_data
                        .into_iter()
                        .filter(|data| !removed_items.contains(data))
                        .collect())
                },
            )
            .await
            .unwrap();
    }

    // search doe (jane removed)
    let doe_search = findex
        .search(
            &new_master_key,
            &new_label,
            Keywords::from_iter([doe_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    check_search_result(&doe_search, &doe_keyword, &robert_doe_location).unwrap();
    check_search_result(&doe_search, &doe_keyword, &john_doe_location).unwrap();

    // Cannot search doe with the old label
    let doe_search = findex
        .search(
            &new_master_key,
            &old_label,
            Keywords::from_iter([doe_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    assert_eq!(doe_search.get(&doe_keyword), Some(&HashSet::new()));

    for i in 1..100 {
        old_label = new_label;
        new_label = Label::random(&mut rng);
        old_master_key = new_master_key;
        new_master_key = findex.keygen();
        findex
            .compact(
                &old_master_key,
                &new_master_key,
                &old_label,
                &new_label,
                i,
                &|indexed_data| async {
                    Ok(indexed_data
                        .into_iter()
                        .filter(|data| !removed_items.contains(data))
                        .collect())
                },
            )
            .await
            .unwrap();

        // search doe (jane removed)
        let doe_search = findex
            .search(
                &new_master_key,
                &new_label,
                Keywords::from_iter([doe_keyword.clone()]),
                &|_| async { Ok(false) },
            )
            .await
            .unwrap();
        check_search_result(&doe_search, &doe_keyword, &robert_doe_location).unwrap();
        check_search_result(&doe_search, &doe_keyword, &john_doe_location).unwrap();
    }

    // Try deleting John Doe from the `doe_keyword`.
    let mut deletions = HashMap::new();
    deletions.insert(
        IndexedValue::Data(john_doe_location.clone()),
        Keywords::from_iter([doe_keyword.clone()]),
    );
    findex
        .delete(
            &new_master_key,
            &new_label,
            IndexedValueToKeywordsMap::from(deletions),
        )
        .await
        .unwrap();

    // Assert John Doe cannot be found by searching for Doe.
    let doe_search = findex
        .search(
            &new_master_key,
            &new_label,
            Keywords::from_iter([doe_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    check_search_result(&doe_search, &doe_keyword, &robert_doe_location).unwrap();
    let doe_search = doe_search.get(&doe_keyword).unwrap();
    assert!(!doe_search.contains(&john_doe_location));
    Ok(())
}

#[actix_rt::test]
async fn test_first_names() -> Result<(), Error<KvStoreError>> {
    const NUM_LOCATIONS: usize = 5;
    // change this to usize::MAX to run a full test
    const MAX_FIRST_NAMES: usize = 1000;

    let mut rng = rand::thread_rng();

    let graph_findex = Findex::new(
        EntryTable::setup(InMemoryEdx::default()),
        ChainTable::setup(InMemoryEdx::default()),
    );

    let naive_findex = Findex::new(
        EntryTable::setup(InMemoryEdx::default()),
        ChainTable::setup(InMemoryEdx::default()),
    );

    let master_key = graph_findex.keygen();

    // Keywords that will be searched later to run tests
    let mut searches: HashSet<String> = HashSet::new();
    let mut first_names_number = 0;
    let mut first_names_total_len = 0;

    let label = Label::from("label");

    let file = File::open("datasets/first_names.txt").unwrap();
    let reader = BufReader::new(file);
    println!("Indexing...");
    for maybe_line in reader.lines() {
        let line = maybe_line.unwrap();
        let first_name = line.as_str();

        first_names_number += 1;
        first_names_total_len += first_name.len();

        // pick one keyword out of about 5 to be searched later
        let die = rng.gen_range(1_i32..=5);
        if die == 1 {
            // select between 3 to keyword length characters
            let die = if first_name.len() <= 3 {
                first_name.len()
            } else {
                rng.gen_range(3..=first_name.len())
            };
            let searched_keyword: String = first_name.chars().take(die).collect();
            searches.insert(searched_keyword);
        }

        // start with graph
        let mut map = HashMap::with_capacity(5);
        for i in 0..NUM_LOCATIONS {
            map.insert(
                IndexedValue::Data(Location::from(format!("{first_name}_{i}").as_bytes())),
                Keywords::from_iter([Keyword::from("france"), Keyword::from(first_name)]),
            );
            add_keyword_graph(&Keyword::from(first_name), MIN_KEYWORD_LENGTH, &mut map);
        }

        graph_findex
            .add(&master_key, &label, IndexedValueToKeywordsMap::from(map))
            .await
            .unwrap();

        // naive Findex
        let mut keywords = HashSet::<Keyword>::new();
        if first_name.len() < MIN_KEYWORD_LENGTH {
            // index as such
            keywords.insert(Keyword::from(first_name));
        } else {
            // index all slices starting from 3
            let mut current: Vec<char> = Vec::new();
            for (i, c) in first_name.chars().enumerate() {
                current.push(c);
                if i + 1 >= MIN_KEYWORD_LENGTH {
                    let current_keyword: String = current.iter().collect();
                    keywords.insert(Keyword::from(current_keyword.as_str()));
                }
            }
        }
        let mut map_naive = HashMap::new();
        for i in 0..NUM_LOCATIONS {
            let iv = IndexedValue::Data(Location::from(format!("{first_name}_{i}").as_str()));
            map_naive.insert(iv, Keywords::from(keywords.clone()));
        }
        naive_findex
            .add(
                &master_key,
                &label,
                IndexedValueToKeywordsMap::from(map_naive),
            )
            .await
            .unwrap();

        if first_names_number % 1000 == 0 {
            println!("    ...{first_names_number}");
        }
        if first_names_number >= MAX_FIRST_NAMES {
            break;
        }
    }
    println!("   ...done");

    println!(
        "Indexed {} keywords with an average length of {} chars and an average of {} locations",
        first_names_number,
        first_names_total_len / first_names_number,
        NUM_LOCATIONS
    );
    println!("Built a list of {} search keywords", searches.len());
    println!(
        "Graphs: table sizes: entry -> {} records, {} kbytes, chain -> {} records, {} kbytes",
        graph_findex.findex_graph.findex_mm.entry_table.len(),
        graph_findex.findex_graph.findex_mm.entry_table.size() / 1024,
        graph_findex.findex_graph.findex_mm.chain_table.len(),
        graph_findex.findex_graph.findex_mm.chain_table.size() / 1024
    );
    println!(
        "Naive: table sizes: entry -> {} records, {} kbytes, chain -> {} records, {} kbytes",
        naive_findex.findex_graph.findex_mm.entry_table.len(),
        naive_findex.findex_graph.findex_mm.entry_table.size() / 1024,
        naive_findex.findex_graph.findex_mm.chain_table.len(),
        naive_findex.findex_graph.findex_mm.chain_table.size() / 1024
    );

    let mut total_results = 0_usize;
    let num_searches = searches.len();
    for s in searches {
        let keywords = Keywords::from_iter([Keyword::from(s.as_str())]);
        let graph_results = graph_findex
            .search(&master_key, &label, keywords.clone(), &|_| async {
                Ok(false)
            })
            .await
            .unwrap();
        assert!(
            !graph_results.is_empty(),
            "No graph results for keyword: {s}! This should not happen"
        );
        total_results += graph_results.len();
        // naive search
        let naive_results = naive_findex
            .search(&master_key, &label, keywords, &|_| async { Ok(false) })
            .await
            .unwrap();
        assert_eq!(
            graph_results.len(),
            naive_results.len(),
            "failed on keyword {s}:\n{graph_results:?}\n{naive_results:?}",
        );
    }
    println!(
        "Graphs: average per search: {} results",
        total_results / num_searches,
    );

    Ok(())
}

#[actix_rt::test]
async fn test_graph_compacting() {
    let mut rng = CsRng::from_entropy();
    let mut indexed_value_to_keywords = HashMap::new();
    let findex = Findex::new(
        EntryTable::setup(InMemoryEdx::default()),
        ChainTable::setup(InMemoryEdx::default()),
    );

    let mut master_key = findex.keygen();

    let rob_keyword = Keyword::from(b"rob".to_vec());
    let doe_keyword = Keyword::from(b"doe".to_vec());
    let john_keyword = Keyword::from(b"john".to_vec());
    let robert_keyword = Keyword::from(b"robert".to_vec());
    let john_doe_location = Location::from("john doe DB location");
    let robert_doe_location = Location::from("robert doe DB location");

    indexed_value_to_keywords.insert(
        IndexedValue::Data(robert_doe_location.clone()),
        Keywords::from_iter([robert_keyword.clone(), doe_keyword.clone()]),
    );
    indexed_value_to_keywords.insert(
        IndexedValue::Data(john_doe_location.clone()),
        Keywords::from_iter([john_keyword.clone(), doe_keyword]),
    );
    add_keyword_graph(
        &john_keyword,
        MIN_KEYWORD_LENGTH,
        &mut indexed_value_to_keywords,
    );
    add_keyword_graph(
        &robert_keyword,
        MIN_KEYWORD_LENGTH,
        &mut indexed_value_to_keywords,
    );

    // Graph upsert
    let mut label = Label::random(&mut rng);
    findex
        .add(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from(indexed_value_to_keywords),
        )
        .await
        .unwrap();

    // Search for "rob"
    let res = findex
        .search(
            &master_key,
            &label,
            Keywords::from_iter([rob_keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await
        .unwrap();
    assert_eq!(res.len(), 1);
    check_search_result(&res, &rob_keyword, &robert_doe_location).unwrap();

    println!(
        "Length of the Entry Table: {}",
        findex.findex_graph.findex_mm.entry_table.len()
    );
    println!(
        "Length of the Chain Table: {}",
        findex.findex_graph.findex_mm.chain_table.len()
    );

    // Compact then search
    for i in 1..100 {
        let old_label = label;
        label = Label::random(&mut rng);
        let new_master_key = findex.keygen();
        findex
            .compact(
                &master_key,
                &new_master_key,
                &old_label,
                &label,
                i,
                &|indexed_data| async { Ok(indexed_data) },
            )
            .await
            .unwrap();
        master_key = new_master_key;

        println!(
            "Length of the Entry Table: {}",
            findex.findex_graph.findex_mm.entry_table.len()
        );
        println!(
            "Length of the Chain Table: {}",
            findex.findex_graph.findex_mm.chain_table.len()
        );

        // Search for "rob"
        let res = findex
            .search(
                &master_key,
                &label,
                Keywords::from_iter([rob_keyword.clone()]),
                &|_| async { Ok(false) },
            )
            .await
            .unwrap();
        assert_eq!(res.len(), 1);
        check_search_result(&res, &rob_keyword, &robert_doe_location).unwrap();
    }
}

#[actix_rt::test]
async fn test_keyword_presence() -> Result<(), Error<KvStoreError>> {
    let mut indexed_value_to_keywords = HashMap::new();

    // direct location robert doe
    let robert_doe_location = Location::from("robert doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Data(robert_doe_location.clone()),
        Keywords::from_iter(["robert", "doe"]),
    );

    // direct location john doe
    let john_doe_location = Location::from("john doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Data(john_doe_location.clone()),
        Keywords::from_iter(["john", "doe"]),
    );

    let findex = Findex::new(
        EntryTable::setup(InMemoryEdx::default()),
        ChainTable::setup(InMemoryEdx::default()),
    );

    let master_key = findex.keygen();
    let label = Label::from("First label.");

    let new_keywords = findex
        .add(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from(indexed_value_to_keywords),
        )
        .await?;

    // the 3 keywords should not be present in the database
    assert_eq!(new_keywords.len(), 3);
    assert!(new_keywords.contains(&Keyword::from("robert")));
    assert!(new_keywords.contains(&Keyword::from("doe")));
    assert!(new_keywords.contains(&Keyword::from("john")));

    // Now insert a Robert Smith
    let mut indexed_value_to_keywords = HashMap::new();
    let robert_smith_location = Location::from("robert smith DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Data(robert_smith_location),
        Keywords::from_iter(["robert", "smith"]),
    );
    let new_keywords = findex
        .add(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from(indexed_value_to_keywords),
        )
        .await?;
    // robert should be present, but not smith
    assert_eq!(new_keywords.len(), 1);
    assert!(!new_keywords.contains(&Keyword::from("robert")));
    assert!(new_keywords.contains(&Keyword::from("smith")));

    // Delete Robert Smith and the junior keyword
    let robert_smith_location = Location::from("robert smith DB location");
    let mut indexed_value_to_keywords = HashMap::new();
    indexed_value_to_keywords.insert(
        IndexedValue::Data(robert_smith_location.clone()),
        Keywords::from_iter(["robert", "smith", "junior"]),
    );
    let new_keywords = findex
        .delete(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from(indexed_value_to_keywords.clone()),
        )
        .await?;
    // robert and smith should be present, but not junior
    assert_eq!(new_keywords.len(), 1);
    assert!(!new_keywords.contains(&Keyword::from("robert")));
    assert!(!new_keywords.contains(&Keyword::from("smith")));
    assert!(new_keywords.contains(&Keyword::from("junior")));

    // however, the first delete create an entry for "junior,
    // therefore deleting again will find it
    let new_keywords = findex
        .delete(
            &master_key,
            &label,
            IndexedValueToKeywordsMap::from(indexed_value_to_keywords.clone()),
        )
        .await?;
    // all should be present
    assert_eq!(new_keywords.len(), 0);

    Ok(())
}

#[actix_rt::test]
async fn test_concurrency() -> Result<(), Error<KvStoreError>> {
    let findex = Arc::new(Findex::new(
        EntryTable::setup(InMemoryEdx::default()),
        ChainTable::setup(InMemoryEdx::default()),
    ));
    let key = Arc::new(findex.keygen());
    let label = Arc::new(Label::from("First label."));
    let keyword = Keyword::from("unique keyword");

    let handles = (0..100)
        .map(|id: usize| {
            let findex = findex.clone();
            let key = key.clone();
            let label = label.clone();
            let keyword = keyword.clone();

            std::thread::spawn(move || {
                let res = block_on(findex.add(
                    &key,
                    &label,
                    IndexedValueToKeywordsMap::from([(
                        IndexedValue::Data(Location::from(id.to_be_bytes().as_slice())),
                        Keywords::from_iter([keyword]),
                    )]),
                ));
                (id, res)
            })
        })
        .collect::<Vec<_>>();

    let mut new_keywords = HashSet::new();
    for h in handles {
        let (id, res) = h.join().unwrap();
        let res = res.unwrap();
        for keyword in res {
            assert!(
                new_keywords.insert(keyword),
                "{id}: same keyword cannot be returned twice."
            );
        }
    }

    assert_eq!(new_keywords, HashSet::from_iter([keyword.clone()]));

    let res = findex
        .search(
            &key,
            &label,
            Keywords::from_iter([keyword.clone()]),
            &|_| async { Ok(false) },
        )
        .await?;

    assert_eq!(
        res.get(&keyword),
        Some(
            (0..100)
                .map(|id: usize| Location::from(id.to_be_bytes().as_slice()))
                .collect()
        )
        .as_ref()
    );

    Ok(())
}
