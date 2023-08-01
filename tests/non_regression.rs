use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
};

use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_findex::{
    in_memory_example::{ExampleError, FindexInMemory},
    parameters::{MASTER_KEY_LENGTH, UID_LENGTH},
    Error, FindexSearch, FindexUpsert, IndexedValue, KeyingMaterial, Keyword, Label, Location,
};
use rand::RngCore;

/// Adds the graph of the given `Keyword` to the given `IndexedValue` to
/// `Keyword`s map.
///
/// - `keyword`             : `Keyword` to upsert as graph
/// - `min_keyword_length`  : number of letters to use as graph root
/// - `map`                 : `IndexedValue` to `Keyword`s map
#[allow(dead_code)]
fn add_keyword_graph(
    keyword: &Keyword,
    min_keyword_length: usize,
    map: &mut HashMap<IndexedValue, HashSet<Keyword>>,
) {
    for i in min_keyword_length..keyword.len() {
        map.entry(IndexedValue::from(Keyword::from(&keyword[..i])))
            .or_default()
            .insert(Keyword::from(&keyword[..i - 1]));
    }
}

#[allow(dead_code)]
async fn write_index() -> Result<(), Error<ExampleError>> {
    const MIN_KEYWORD_LENGTH: usize = 3;
    const MAX_NUM_LOCATIONS: usize = 20;
    const MAX_FIRST_NAMES: usize = 1000;

    let mut rng = rand::thread_rng();
    let master_key = KeyingMaterial::new(&mut rng);
    let label = Label::random(&mut rng);

    let mut findex = FindexInMemory::default();

    let reader = BufReader::new(File::open("datasets/first_names.txt").unwrap());
    for maybe_line in reader.lines().take(MAX_FIRST_NAMES) {
        let line = maybe_line.unwrap();
        let first_name = line.as_str();

        let n_locations = rng.next_u64() as usize % MAX_NUM_LOCATIONS;

        let mut map = HashMap::with_capacity(n_locations);
        for i in 0..n_locations {
            map.insert(
                IndexedValue::Location(Location::from(format!("{first_name}_{i}").as_bytes())),
                HashSet::from_iter([Keyword::from(first_name)]),
            );
        }

        add_keyword_graph(&Keyword::from(first_name), MIN_KEYWORD_LENGTH, &mut map);

        findex.add(&master_key, &label, map).await?;
    }

    std::fs::write("datasets/serialized_index", findex.dump_tables()?).unwrap();
    std::fs::write("datasets/key", master_key.serialize()?).unwrap();
    std::fs::write("datasets/label", label.serialize()?).unwrap();

    let keyword = Keyword::from("Abd");
    let res = findex
        .search(&master_key, &label, HashSet::from_iter([keyword.clone()]))
        .await?;

    let mut buffer = BufWriter::new(File::create("datasets/test_vector.txt").unwrap());
    for result in res.get(&keyword).unwrap() {
        buffer.write_all(result).unwrap();
        buffer.write_all(b"\n").unwrap();
    }
    buffer.flush().unwrap();

    Ok(())
}

#[actix_rt::test]
async fn test_non_regression() -> Result<(), Error<ExampleError>> {
    // Uncomment to generate new test data.
    // write_index().await?;

    let mut findex = FindexInMemory::<UID_LENGTH>::default();
    let serialized_index = std::fs::read("datasets/serialized_index").unwrap();
    findex.load_tables(&serialized_index)?;

    println!("Entry Table length: {}", findex.entry_table_len());
    println!("Entry Table size: {}", findex.entry_table_size());
    println!("Chain Table length: {}", findex.chain_table_len());
    println!("Chain Table size: {}", findex.chain_table_size());

    let master_key =
        KeyingMaterial::<MASTER_KEY_LENGTH>::deserialize(&std::fs::read("datasets/key").unwrap())?;
    let label = Label::deserialize(&std::fs::read("datasets/label").unwrap())?;

    let keyword = Keyword::from("Abd");
    let res = findex
        .search(&master_key, &label, HashSet::from_iter([keyword.clone()]))
        .await?
        .remove(&keyword)
        .unwrap();

    let mut test_vector = HashSet::new();
    let reader = BufReader::new(File::open("datasets/test_vector.txt").unwrap());
    for maybe_line in reader.lines() {
        let line = maybe_line.unwrap();
        test_vector.insert(Location::from(line.as_bytes().to_vec()));
    }

    assert_eq!(res, test_vector);

    Ok(())
}
