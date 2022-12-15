# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- `FindexCallbacks` trait to centralize callback definitions

### Changed

- `FindexSearch::search()` returns `HashMap<Keyword, HashSet<IndexedValue>>`
- `FindexUpsert::upsert()` inverts map first to match crypto definition
- `upsert_wrapper()` in python interface takes `HashMap<IndexedValuePy, Vec<&str>>`
- `KeyWord` -> `Keyword`

---

## [0.12.0] - 2022-12-12

### Added

- Documentation
- test for long indexed value

### Changed

- Length of the keyword hashes is now `Keyword::HASH_LENGTH`

### Removed

- `FindexGraphUpsert` trait

---

## [0.11.2] - 2022-12-08

### Fixed

- fix in wasm: do not erase previous next_words
- fix ffi allocation

---

## [0.11.1] - 2022-12-05

### Fixed

- fix WASM interface

---

## [0.11.0] - 2022-12-02

### Added

- python interface using PyO3

### Changed

- `Kwi` is drawn at random
- use KMAC128 to generate UIDs
- use SHAKE128 to extend `K` and `Kwi`
- store hash (SHA3-256) of `wi` in Entry Table
- use fixed length structure to store indexed values in Chain Table

### Fixed

### Removed

- `K_star`

---

## [0.10.1] - 2022-10-27

### Added

### Changed

- Mutualize `wasm` implementation with existing traits (search, upsert) using the feature `async_fn_in_trait`

### Fixed

### Removed

---

## [0.10.0] - 2022-10-26

### Added

### Changed

- change wasm packaging

### Fixed

### Removed

---

## [0.9.0] - 2022-10-24

### Added

### Changed

- `wasm` api changes
  - full typing
  - no custom conversions but with direct reflection in JS types

### Fixed

### Removed

---

## [0.8.0] - 2022-10-19

### Added

### Changed

- use `Shake256` to derive keys
- use constant generics instead of `GenericArray`
- replace `Hc128` by `ChaCha12Rng` as RNG

### Fixed

- command lines to generate `ffi` and `wasm` in README
- fix bug in `unchain_entry_table_value`

### Removed

- conversion from `&str` to `Word` or `Location` -> use `new()` instead

---

## [0.7.2] - 2022-10-14

### Changed

- CI: use KMS version from Gitlab variable

---

## [0.7.1] - 2022-10-10

### Changed

- CI:
  - rename client libraries to `cloudproof_*`
  - regroup all artifacts

---

## [0.7.0] - 2022-09-27

### Added

- `FindexGraphUpsert` trait

### Changed

- `FindexSearch` trait -> now uses graphs via recursive calls
- `MasterKeys::random()` takes a CSRNG as argument

---

## [0.6.1] - 2022-09-26

### Fixed

- Fixed allocation size in fetch callbacks + retry in case of insufficient size

---

## [0.6.0] - 2022-09-22

### Added

- Indexes compaction + add FFI and Wasm interfaces entry point

---

## [0.5.2] - 2022-09-16

### Fixed

- Fix cargo publish on tags

---

## [0.5.1] - 2022-09-14

### Fixed

- Fixed cosmian_js_lib CI: use postgrest/postgres services and update KMS version to 2.2.0

---

## [0.5.0] - 2022-09-07

### Added

- Added the possibility to index pointers to a "next word"
- Added a complete unit test on core

### Fixed

- Fixed passing only k and not all the master keys on search
- Fixed that Locations and Words may be arbitrary bytes and not only strings on the FFI

---

## [0.4.1] - 2022-08-31

### Added

- Auto NPM publish on tag release
- Enable/Run KMS for Java tests
- Enable Typescript tests on `cosmian_js_lib`

### Changed

- Reduce benchmarks sample count

---

## [0.4.0] - 2022-08-25

### Added

### Changed

- Rename project name to `cosmian_findex` du to NPM publish (findex is already taken)

### Fixed

- Fix Findex keys zeroization via updating `crypto_core` to 2.0.0

### Removed

---

## [0.3.1] - 2022-08-22

### Added

### Changed

- add deserializer for MasterKeys where K and K\* are generic types

### Fixed

### Removed

---

## [0.3.0] - 2022-08-19

### Added

- Trigger `cosmian_java_lib` tests on Findex build
- Add WASM functions to perform upsert and search of Findex algorithm

### Changed

- `core/mod.rs` now only re-export structs and Traits useful to the API user, and nothing else
- There are now dedicated structs for Entry Table and Chain Table, keys and values, which are all in `core/structs.rs` because carrying bytes around is really not explicit and prone to errors. The additional benefit of using structs is that serialization, conversions, etc.. are within the structs and do not pollute the core algorithms
- de-hardcoding: the lengths of the of the keys for Entry Table and Chain Table are now de-hardcoded and passed as const generics respectively `WORD_HASH_LENGTH` and `R_LENGTH`. There is no reason for them to be tied to the Symmetric Crypto Key length as they were before. I guess 32 is a reasonable value for both and is hardcoded at a higher level for the user API.
- `upsert` is completely rewritten and should do less unnecessary loops as well as better use caching for speed. The minimum achievable is O(K) where K is the number of unique tuples (Word, Location) and is also the number of inserts in the Chain Table
- update to `crypto_core` in order to use `hkdf_256` with const generic
- structs in keys.rs have been moved to `core` since they are used there
- Some core elements are made public (struct elements, and functions from FindexUpsert and FindexSearch) to be used from wasm functions

### Fixed

### Removed

---

## [0.2.3] - 2022-07-22

### Added

- Bench mechanism via `cargo bench --features sqlite`
- Apply ANSSI Secure Rust rules

### Changed

- Replace JSON serialization with LEB128 serialization in callbacks
- In Entry and Chain Tables, use BLOB in SQL schemas instead of TEXT

### Fixed

### Removed

- Hex encoding removed

---

## [0.2.2] - 2022-07-13

### Added

### Changed

- Keys (de)serialization in base64
- FFI functions renamed for uniformize
- Update `cosmian_crypto_base` to v2.0

### Fixed

- FetchEntry and FetchChain callbacks returns HashMap instead of `Vec<Vec>`

### Removed

- Remove/simplify SetOutputBufferCallback: if output pre-allocated size is not enough, returns the size to allocate

---

## [0.2.1] - 2022-07-06

### Added

### Changed

- Replace custom serialization with JSON serialization
- Revisit callbacks declaration:
  - to get a return code
  - to dynamically allocate buffer size from DB request
- Reorder source code tree

### Fixed

### Removed

---

## [0.2.0] - 2022-07-01

### Added

- First version of Findex with bulk insertions and bulk words search
- Use of callbacks to get all SSE logic in same place
- Test with Python

### Changed

### Fixed

### Removed
