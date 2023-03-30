#![cfg(feature = "in_memory")]
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader},
};

use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
use cosmian_findex::{
    in_memory_example::{ExampleError, FindexInMemory},
    parameters::*,
    Error, FindexCallbacks, FindexCompact, FindexSearch, FindexUpsert, IndexedValue,
    KeyingMaterial, Keyword, Label, Location,
};
use rand::Rng;

const MIN_KEYWORD_LENGTH: usize = 3;

/// Converts the given strings as a `HashSet` of Keywords.
///
/// - `keywords`    : strings to convert
fn hashset_keywords(keywords: &[&'static str]) -> HashSet<Keyword> {
    keywords
        .iter()
        .map(|keyword| Keyword::from(*keyword))
        .collect()
}

/// Computes the index graph of the given `Keyword`.
///
/// - `keyword`             : `Keyword` of which to compute the index graph
/// - `min_keyword_length`  : number of letters to use as graph root
fn compute_index_graph(
    keyword: &Keyword,
    min_keyword_length: usize,
) -> HashMap<IndexedValue, HashSet<Keyword>> {
    if keyword.len() <= min_keyword_length {
        return HashMap::new();
    }
    let mut res = HashMap::with_capacity(keyword.len() - min_keyword_length);
    for i in min_keyword_length..keyword.len() {
        let indexing_keyword = Keyword::from(&keyword[..i]);
        let indexed_value = IndexedValue::from(Keyword::from(&keyword[..=i]));
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
    map: &mut HashMap<IndexedValue, HashSet<Keyword>>,
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
) {
    let results = search_results.get(keyword).unwrap();
    assert!(results.contains(location));
}

#[actix_rt::test]
async fn test_findex() -> Result<(), Error<ExampleError>> {
    let mut rng = CsRng::from_entropy();

    let label = Label::random(&mut rng);

    let mut master_key = KeyingMaterial::new(&mut rng);

    let mut indexed_value_to_keywords = HashMap::new();

    // direct location robert doe
    let robert_doe_location = Location::from("robert doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Location(robert_doe_location.clone()),
        hashset_keywords(&["robert", "doe"]),
    );

    // direct location john doe
    let john_doe_location = Location::from("john doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Location(john_doe_location.clone()),
        hashset_keywords(&["john", "doe"]),
    );

    // direct location for rob...
    let rob_location = Location::from("rob DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Location(rob_location.clone()),
        hashset_keywords(&["rob"]),
    );
    // ... and indirection to robert
    indexed_value_to_keywords.insert(
        IndexedValue::NextKeyword(Keyword::from("robert")),
        hashset_keywords(&["rob"]),
    );

    let mut findex = FindexInMemory::default();
    findex
        .upsert(
            indexed_value_to_keywords,
            HashMap::new(),
            &master_key,
            &label,
        )
        .await?;

    let robert_keyword = Keyword::from("robert");
    let rob_keyword = Keyword::from("rob");
    let doe_keyword = Keyword::from("doe");

    // search robert
    let robert_search = findex
        .search(
            &HashSet::from_iter(vec![robert_keyword.clone()]),
            &master_key,
            &label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    check_search_result(&robert_search, &robert_keyword, &robert_doe_location);

    // cannot find robert with wrong label
    let robert_search = findex
        .search(
            &HashSet::from_iter(vec![robert_keyword.clone()]),
            &master_key,
            &Label::random(&mut rng),
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    assert_eq!(0, robert_search.len());

    // search doe
    let doe_search = findex
        .search(
            &HashSet::from_iter(vec![doe_keyword.clone()]),
            &master_key,
            &label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    check_search_result(&doe_search, &doe_keyword, &robert_doe_location);
    check_search_result(&doe_search, &doe_keyword, &john_doe_location);

    // search rob without graph search
    findex.set_check_progress_callback_next_keyword(true);
    let rob_search = findex
        .search(
            &HashSet::from_iter(vec![rob_keyword.clone()]),
            &master_key,
            &label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    findex.set_check_progress_callback_next_keyword(false);
    check_search_result(&rob_search, &rob_keyword, &rob_location);

    // search rob with graph search
    let rob_search = findex
        .search(
            &HashSet::from_iter(vec![rob_keyword.clone()]),
            &master_key,
            &label,
            usize::MAX,
            usize::MAX,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    check_search_result(&rob_search, &rob_keyword, &robert_doe_location);
    check_search_result(&rob_search, &rob_keyword, &rob_location);

    //
    // Add Jane Doe to indexes
    //

    let mut indexed_value_to_keywords = HashMap::new();
    let jane_doe_location = Location::from("jane doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Location(jane_doe_location.clone()),
        hashset_keywords(&["jane", "doe"]),
    );
    findex
        .upsert(
            indexed_value_to_keywords,
            HashMap::new(),
            &master_key,
            &label,
        )
        .await?;

    // search jane
    let jane_keyword = Keyword::from("jane");
    let jane_search = findex
        .search(
            &HashSet::from_iter(vec![jane_keyword.clone()]),
            &master_key,
            &label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    check_search_result(&jane_search, &jane_keyword, &jane_doe_location);

    // search robert (no change)
    let robert_search = findex
        .search(
            &HashSet::from_iter(vec![robert_keyword.clone()]),
            &master_key,
            &label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    check_search_result(&robert_search, &robert_keyword, &robert_doe_location);

    // search doe (jane added)
    let doe_search = findex
        .search(
            &HashSet::from_iter(vec![doe_keyword.clone()]),
            &master_key,
            &label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    check_search_result(&doe_search, &doe_keyword, &jane_doe_location);
    check_search_result(&doe_search, &doe_keyword, &robert_doe_location);
    check_search_result(&doe_search, &doe_keyword, &john_doe_location);

    // search rob (no change)
    findex.set_check_progress_callback_next_keyword(true);
    let rob_search = findex
        .search(
            &HashSet::from_iter(vec![rob_keyword.clone()]),
            &master_key,
            &label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    findex.set_check_progress_callback_next_keyword(false);
    check_search_result(&rob_search, &rob_keyword, &rob_location);

    let mut new_label = Label::random(&mut rng);

    // If nothing is removed, a lot of small compact should not affect the search
    // results
    for i in 1..=100 {
        println!("Compacting {i}/100");
        new_label = Label::random(&mut rng);
        let new_master_key = KeyingMaterial::new(&mut rng);
        findex
            .compact(i, &master_key, &new_master_key, &new_label)
            .await?;
        master_key = new_master_key;

        // search doe
        let doe_search = findex
            .search(
                &HashSet::from_iter(vec![doe_keyword.clone()]),
                &master_key,
                &new_label,
                usize::MAX,
                0,
                SECURE_FETCH_CHAINS_BATCH_SIZE,
                0,
            )
            .await?;
        check_search_result(&doe_search, &doe_keyword, &robert_doe_location);
        check_search_result(&doe_search, &doe_keyword, &john_doe_location);
        check_search_result(&doe_search, &doe_keyword, &jane_doe_location);
    }

    findex.remove_location(jane_doe_location);
    let new_master_key = KeyingMaterial::new(&mut rng);
    findex
        .compact(1, &master_key, &new_master_key, &new_label)
        .await?;
    master_key = new_master_key;

    // search jane
    let jane_search = findex
        .search(
            &HashSet::from_iter(vec![jane_keyword.clone()]),
            &master_key,
            &new_label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    // Jane is not indexed anymore.
    assert_eq!(jane_search.get(&jane_keyword), None);

    // search doe (jane removed)
    let doe_search = findex
        .search(
            &HashSet::from_iter(vec![doe_keyword.clone()]),
            &master_key,
            &new_label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    check_search_result(&doe_search, &doe_keyword, &robert_doe_location);
    check_search_result(&doe_search, &doe_keyword, &john_doe_location);

    // Cannot search doe with the old label
    let doe_search = findex
        .search(
            &HashSet::from_iter(vec![doe_keyword.clone()]),
            &master_key,
            &label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    assert_eq!(0, doe_search.len());

    for i in 1..=100 {
        println!("Compacting {i}/100");
        new_label = Label::random(&mut rng);
        let new_master_key = KeyingMaterial::new(&mut rng);
        findex
            .compact(i, &master_key, &new_master_key, &new_label)
            .await?;
        master_key = new_master_key;
    }

    // search doe (jane removed)
    let doe_search = findex
        .search(
            &HashSet::from_iter(vec![doe_keyword.clone()]),
            &master_key,
            &new_label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    check_search_result(&doe_search, &doe_keyword, &robert_doe_location);
    check_search_result(&doe_search, &doe_keyword, &john_doe_location);

    // Cannot search doe with the old label
    let doe_search = findex
        .search(
            &hashset_keywords(&["doe"]),
            &master_key,
            &label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    assert_eq!(0, doe_search.len());

    for i in 1..100 {
        new_label = Label::random(&mut rng);
        let new_master_key = KeyingMaterial::new(&mut rng);
        findex
            .compact(i, &master_key, &new_master_key, &new_label)
            .await?;
        master_key = new_master_key;

        // search doe (jane removed)
        let doe_search = findex
            .search(
                &HashSet::from_iter(vec![doe_keyword.clone()]),
                &master_key,
                &new_label,
                usize::MAX,
                0,
                SECURE_FETCH_CHAINS_BATCH_SIZE,
                0,
            )
            .await?;
        check_search_result(&doe_search, &doe_keyword, &robert_doe_location);
        check_search_result(&doe_search, &doe_keyword, &john_doe_location);
    }

    // Try deleting John Doe from the `doe_keyword`.
    let mut deletions = HashMap::new();
    deletions.insert(
        IndexedValue::from(john_doe_location.clone()),
        HashSet::from_iter(vec![doe_keyword.clone()]),
    );
    findex
        .upsert(HashMap::new(), deletions, &master_key, &new_label)
        .await?;

    // Assert John Doe cannot be found by searching for Doe.
    let doe_search = findex
        .search(
            &HashSet::from_iter(vec![doe_keyword.clone()]),
            &master_key,
            &new_label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await?;
    let doe_search = doe_search.get(&doe_keyword).unwrap();
    assert!(!doe_search.contains(&john_doe_location));

    Ok(())
}

#[actix_rt::test]
async fn test_first_names() -> Result<(), Error<ExampleError>> {
    const NUM_LOCATIONS: usize = 5;
    // change this to usize::MAX to run a full test
    const MAX_FIRST_NAMES: usize = 1000;
    let mut rng = rand::thread_rng();
    let master_key = KeyingMaterial::new(&mut rng);
    let mut graph_findex = FindexInMemory::default();
    let mut naive_findex = FindexInMemory::default();

    // Keywords that will be searched later to run tests
    let mut searches: HashSet<String> = HashSet::new();
    let mut first_names_number = 0;
    let mut first_names_total_len = 0;

    let label = Label::random(&mut rng);

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
                IndexedValue::Location(Location::from(format!("{first_name}_{i}").as_bytes())),
                HashSet::from_iter(vec![Keyword::from("france"), Keyword::from(first_name)]),
            );
            add_keyword_graph(&Keyword::from(first_name), MIN_KEYWORD_LENGTH, &mut map);
        }

        graph_findex
            .upsert(map, HashMap::new(), &master_key, &label)
            .await?;

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
            let iv = IndexedValue::Location(Location::from(format!("{first_name}_{i}").as_str()));
            map_naive.insert(iv, keywords.clone());
        }
        naive_findex
            .upsert(map_naive, HashMap::new(), &master_key, &label)
            .await?;

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
        graph_findex.entry_table_len(),
        graph_findex.entry_table_size() / 1024,
        graph_findex.chain_table_len(),
        graph_findex.chain_table_size() / 1024
    );
    println!(
        "Naive: table sizes: entry -> {} records, {} kbytes, chain -> {} records, {} kbytes",
        naive_findex.entry_table_len(),
        naive_findex.entry_table_size() / 1024,
        naive_findex.chain_table_len(),
        naive_findex.chain_table_size() / 1024
    );

    let mut total_results = 0_usize;
    let num_searches = searches.len();
    for s in searches {
        let keywords = HashSet::from_iter(vec![Keyword::from(s.as_str())]);
        let graph_results = graph_findex
            .search(
                &keywords,
                &master_key,
                &label,
                usize::MAX,
                usize::MAX,
                SECURE_FETCH_CHAINS_BATCH_SIZE,
                0,
            )
            .await?;
        assert!(
            !graph_results.is_empty(),
            "No graph results for keyword: {s}! This should not happen"
        );
        total_results += graph_results.len();
        // naive search
        let naive_results = naive_findex
            .search(
                &keywords,
                &master_key,
                &label,
                usize::MAX,
                usize::MAX,
                SECURE_FETCH_CHAINS_BATCH_SIZE,
                0,
            )
            .await?;
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
    let mut master_key = KeyingMaterial::new(&mut rng);
    let mut findex = FindexInMemory::default();
    let mut indexed_value_to_keywords = HashMap::new();

    // location robert doe
    let robert_doe_location = Location::from("robert doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Location(robert_doe_location.clone()),
        hashset_keywords(&["robert", "doe"]),
    );

    // location john doe
    let john_doe_location = Location::from("john doe DB location");
    indexed_value_to_keywords.insert(
        IndexedValue::Location(john_doe_location.clone()),
        hashset_keywords(&["john", "doe"]),
    );

    add_keyword_graph(
        &Keyword::from("john"),
        MIN_KEYWORD_LENGTH,
        &mut indexed_value_to_keywords,
    );
    add_keyword_graph(
        &Keyword::from("robert"),
        MIN_KEYWORD_LENGTH,
        &mut indexed_value_to_keywords,
    );

    // Graph upsert
    let mut label = Label::random(&mut rng);
    findex
        .upsert(
            indexed_value_to_keywords,
            HashMap::new(),
            &master_key,
            &label,
        )
        .await
        .unwrap();

    // Search for "rob"
    let robert_keyword = Keyword::from(b"rob".to_vec());
    let res = findex
        .search(
            &HashSet::from_iter(vec![robert_keyword.clone()]),
            &master_key,
            &label,
            usize::MAX,
            usize::MAX,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await
        .unwrap();
    assert_eq!(res.len(), 1);
    check_search_result(&res, &robert_keyword, &robert_doe_location);

    println!("Length of the Entry Table: {}", findex.entry_table_len());
    println!("Length of the Chain Table: {}", findex.chain_table_len());

    println!(
        "Entry Table (before compacting): {:?}",
        <FindexInMemory<UID_LENGTH> as FindexCallbacks<
            ExampleError,
            UID_LENGTH,
        >>::fetch_all_entry_table_uids(&findex)
        .await
        .unwrap()
    );

    // Compact then search
    for i in 1..100 {
        label = Label::random(&mut rng);
        let new_master_key = KeyingMaterial::new(&mut rng);
        findex
            .compact(i, &master_key, &new_master_key, &label)
            .await
            .unwrap();
        master_key = new_master_key;

        println!("Length of the Entry Table: {}", findex.entry_table_len());
        println!("Length of the Chain Table: {}", findex.chain_table_len());

        // Search for "rob"
        let res = findex
            .search(
                &HashSet::from_iter(vec![robert_keyword.clone()]),
                &master_key,
                &label,
                usize::MAX,
                usize::MAX,
                SECURE_FETCH_CHAINS_BATCH_SIZE,
                0,
            )
            .await
            .unwrap();
        assert_eq!(res.len(), 1);
        check_search_result(&res, &robert_keyword, &robert_doe_location);
    }
}

#[cfg(feature = "live_compact")]
#[actix_rt::test]
async fn test_live_compacting() {
    use cosmian_findex::FindexLiveCompact;

    let mut rng = CsRng::from_entropy();
    let mut findex = FindexInMemory::default();

    let label = Label::random(&mut rng);
    let master_key = KeyingMaterial::new(&mut rng);

    // Direct location robert doe.
    let robert_doe_location = Location::from("robert doe DB location");
    let mut indexed_value_to_keywords = HashMap::new();
    indexed_value_to_keywords.insert(
        IndexedValue::Location(robert_doe_location.clone()),
        hashset_keywords(&["robert", "doe"]),
    );

    for _ in 0..100 {
        // Add some keywords.
        findex
            .upsert(
                indexed_value_to_keywords.clone(),
                HashMap::new(),
                &master_key,
                &label,
            )
            .await
            .unwrap();

        // Remove them.
        findex
            .upsert(
                HashMap::new(),
                indexed_value_to_keywords.clone(),
                &master_key,
                &label,
            )
            .await
            .unwrap();
    }
    // Add some keywords.
    findex
        .upsert(
            indexed_value_to_keywords.clone(),
            HashMap::new(),
            &master_key,
            &label,
        )
        .await
        .unwrap();

    // Check keywords have been correctly insterted.
    let robert_keyword = Keyword::from("robert");
    let doe_keyword = Keyword::from("doe");
    // Search Robert.
    let robert_search = findex
        .search(
            &HashSet::from_iter(vec![robert_keyword.clone()]),
            &master_key,
            &label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await
        .unwrap();
    check_search_result(&robert_search, &robert_keyword, &robert_doe_location);
    // Search Doe.
    let doe_search = findex
        .search(
            &HashSet::from_iter(vec![doe_keyword.clone()]),
            &master_key,
            &label,
            usize::MAX,
            0,
            SECURE_FETCH_CHAINS_BATCH_SIZE,
            0,
        )
        .await
        .unwrap();
    check_search_result(&doe_search, &doe_keyword, &robert_doe_location);

    // Compact enough times to be sure all entries have been compacted.
    for _ in 0..100 {
        findex.live_compact(&master_key, 80).await.unwrap();
    }

    // After compaction, there should still be two entries in the Entry Table.
    assert_eq!(findex.entry_table_len(), 2);
    // But deletions should have been simplified (only two locations indexed per
    // chain -> one line per chain -> 2 lines)
    assert_eq!(findex.chain_table_len(), 2);
}
