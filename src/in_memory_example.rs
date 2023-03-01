use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
use rand::Rng;

use crate::{
    parameters::{
        DemScheme, KmacKey, BLOCK_LENGTH, DEM_KEY_LENGTH, KMAC_KEY_LENGTH, KWI_LENGTH,
        MASTER_KEY_LENGTH, TABLE_WIDTH, UID_LENGTH,
    },
    EncryptedTable, FindexCallbacks, FindexCompact, FindexSearch, FindexUpsert, IndexedValue,
    Keyword, Location, Uid, UpsertData,
};

#[derive(Debug)]
pub struct ExampleError(String);

impl Display for ExampleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ExampleError {}

impl crate::CallbackError for ExampleError {}

#[derive(Default, Clone)]
pub struct FindexInMemory<const UID_LENGTH: usize> {
    entry_table: EncryptedTable<UID_LENGTH>,
    chain_table: EncryptedTable<UID_LENGTH>,
    removed_locations: HashSet<Location>,
    check_progress_callback_next_keyword: bool,
}

impl<const UID_LENGTH: usize> FindexInMemory<UID_LENGTH> {
    /// The entry table length (number of records)
    #[must_use]
    pub fn entry_table_len(&self) -> usize {
        self.entry_table.len()
    }

    /// The entry table size in bytes
    #[must_use]
    pub fn entry_table_size(&self) -> usize {
        let mut size = 0;
        for (k, v) in self.entry_table.iter() {
            size += k.len() + v.len();
        }
        size
    }

    /// The chain table length (number of records)
    #[must_use]
    pub fn chain_table_len(&self) -> usize {
        self.chain_table.len()
    }

    /// The entry table size in bytes
    #[must_use]
    pub fn chain_table_size(&self) -> usize {
        let mut size = 0;
        for (k, v) in self.chain_table.iter() {
            size += k.len() + v.len();
        }
        size
    }

    pub fn remove_location(&mut self, location: Location) {
        self.removed_locations.insert(location);
    }

    pub fn set_check_progress_callback_next_keyword(&mut self, value: bool) {
        self.check_progress_callback_next_keyword = value;
    }
}

impl<const UID_LENGTH: usize> FindexCallbacks<ExampleError, UID_LENGTH>
    for FindexInMemory<UID_LENGTH>
{
    async fn progress(
        &self,
        results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, ExampleError> {
        if self.check_progress_callback_next_keyword {
            let keyword = &Keyword::from("rob");
            let results = results
                .get(keyword)
                .ok_or_else(|| {
                    ExampleError(format!(
                        "Cannot find keyword {keyword:?} in search results {results:?}"
                    ))
                })
                .unwrap();
            assert!(results.contains(&IndexedValue::NextKeyword(Keyword::from("robert"))));
        }
        // do not stop recursion.
        Ok(true)
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, ExampleError> {
        //println!(
        //"Fetch {} items from the Entry Table",
        //entry_table_uids.len()
        //);
        let mut entry_table_items = EncryptedTable::default();
        for keyword_hash in entry_table_uids {
            if let Some(value) = self.entry_table.get(keyword_hash) {
                entry_table_items.insert(keyword_hash.clone(), value.clone());
            }
        }
        Ok(entry_table_items)
    }

    async fn fetch_chain_table(
        &self,
        chain_uids: &HashSet<Uid<UID_LENGTH>>,
    ) -> Result<EncryptedTable<UID_LENGTH>, ExampleError> {
        //println!("Fetch {} items from the Chain Table", chain_uids.len());
        Ok(chain_uids
            .iter()
            .filter_map(|uid| {
                self.chain_table
                    .get(uid)
                    .map(|value| (uid.clone(), value.clone()))
            })
            .collect::<HashMap<Uid<UID_LENGTH>, Vec<u8>>>()
            .into())
    }

    async fn upsert_entry_table(
        &mut self,
        modifications: &UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, ExampleError> {
        //println!("Upsert {} items in the Entry Table", modifications.len());
        let mut rng = CsRng::from_entropy();
        let mut rejected = EncryptedTable::default();
        // Simulate insertion failures.
        for (uid, (old_value, new_value)) in modifications.iter() {
            // Reject insert with probability 0.2.
            if self.entry_table.contains_key(uid) && rng.gen_range(0..5) == 0 {
                rejected.insert(uid.clone(), old_value.clone().unwrap_or_default());
            } else {
                self.entry_table.insert(uid.clone(), new_value.clone());
            }
        }
        //println!("{} rejected upsertions", rejected.len());
        Ok(rejected)
    }

    async fn insert_chain_table(
        &mut self,
        items: &EncryptedTable<UID_LENGTH>,
    ) -> Result<(), ExampleError> {
        //println!("Insert {} items in the Chain Table", items.len());
        for (uid, value) in items.iter() {
            if self.chain_table.contains_key(uid) {
                return Err(ExampleError(format!(
                    "Conflict in Chain Table for UID: {uid:?}"
                )));
            }
            self.chain_table.insert(uid.clone(), value.clone());
        }
        Ok(())
    }

    fn update_lines(
        &mut self,
        chain_table_uids_to_remove: HashSet<Uid<UID_LENGTH>>,
        new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), ExampleError> {
        //println!(
        //"Remove {} items from the Chain Table",
        //chain_table_uids_to_remove.len()
        //);
        //println!(
        //"Insert {} items to the Chain Table",
        //new_encrypted_chain_table_items.len()
        //);
        //println!(
        //"Insert {} items to the Entry Table",
        //new_encrypted_entry_table_items.len()
        //);

        self.entry_table = EncryptedTable::default();

        for new_encrypted_entry_table_item in new_encrypted_entry_table_items.iter() {
            self.entry_table.insert(
                new_encrypted_entry_table_item.0.clone(),
                new_encrypted_entry_table_item.1.clone(),
            );
        }

        for new_encrypted_chain_table_item in new_encrypted_chain_table_items.iter() {
            self.chain_table.insert(
                new_encrypted_chain_table_item.0.clone(),
                new_encrypted_chain_table_item.1.clone(),
            );
        }

        for removed_chain_table_uid in chain_table_uids_to_remove {
            self.chain_table.remove(&removed_chain_table_uid);
        }

        Ok(())
    }

    fn list_removed_locations(
        &self,
        _: &HashSet<Location>,
    ) -> Result<HashSet<Location>, ExampleError> {
        Ok(self.removed_locations.iter().cloned().collect())
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<HashSet<Uid<UID_LENGTH>>, ExampleError> {
        let uids: HashSet<Uid<UID_LENGTH>> = self.entry_table.keys().cloned().collect();
        Ok(uids)
    }
}

impl
    FindexSearch<
        UID_LENGTH,
        BLOCK_LENGTH,
        TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
        ExampleError,
    > for FindexInMemory<UID_LENGTH>
{
}

impl
    FindexUpsert<
        UID_LENGTH,
        BLOCK_LENGTH,
        TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
        ExampleError,
    > for FindexInMemory<UID_LENGTH>
{
}

impl
    FindexCompact<
        UID_LENGTH,
        BLOCK_LENGTH,
        TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        DEM_KEY_LENGTH,
        KmacKey,
        DemScheme,
        ExampleError,
    > for FindexInMemory<UID_LENGTH>
{
}

#[cfg(test)]

mod examples {
    use std::{
        collections::{HashMap, HashSet},
        fs::File,
        io::{BufRead, BufReader},
    };

    use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
    use rand::Rng;

    use super::ExampleError;
    use crate::{
        in_memory_example::FindexInMemory,
        parameters::{SECURE_FETCH_CHAINS_BATCH_SIZE, UID_LENGTH},
        Error, FindexCallbacks, FindexCompact, FindexSearch, FindexUpsert, IndexedValue,
        KeyingMaterial, Keyword, Label, Location,
    };

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
            .upsert(indexed_value_to_keywords, &master_key, &label)
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
            .upsert(indexed_value_to_keywords, &master_key, &label)
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

        let file = File::open("tests/first_names.txt").unwrap();
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

            graph_findex.upsert(map, &master_key, &label).await?;

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
                let iv =
                    IndexedValue::Location(Location::from(format!("{first_name}_{i}").as_str()));
                map_naive.insert(iv, keywords.clone());
            }
            naive_findex.upsert(map_naive, &master_key, &label).await?;

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
            .upsert(indexed_value_to_keywords, &master_key, &label)
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
}
