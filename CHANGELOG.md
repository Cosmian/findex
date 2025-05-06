# Changelog

All notable changes to this project will be documented in this file.

## [7.1.0] - 2025-05-06

### 🚀 Features

- Extract memory encryption: pass an encrypted memory to Findex::new ([#110](https://github.com/Cosmian/findex/pull/110))
- Use `tostring` to easy guard condition ([#134](https://github.com/Cosmian/findex/pull/134))
- Add Redis Persistent Cache ([#132](https://github.com/Cosmian/findex/pull/132))
- Re-use secrets, symmetric key, values, and CsRng from CryptoCore ([#130](https://github.com/Cosmian/findex/pull/130))
- Support PostgreSQL ([#126](https://github.com/Cosmian/findex/pull/126))
- Support SQLite3 ([#125](https://github.com/Cosmian/findex/pull/125))

### 🧪 Testing

- Add a test to detect concurrency errors originating from different memory interfaces using the same DB ([#133](https://github.com/Cosmian/findex/pull/133))
- Test/isolate interface test  ([#129](https://github.com/Cosmian/findex/pull/129))
- Test/collisions ([#128](https://github.com/Cosmian/findex/pull/128))

### ⚙️ Miscellaneous Tasks

- Benches:
  - Write generic benches ([#136](https://github.com/Cosmian/findex/pull/136) and [#131](https://github.com/Cosmian/findex/pull/131))
  - Add PostgreSQL benches ([#135](https://github.com/Cosmian/findex/pull/135))
  - Use cargo-bench with Redis container

## [7.0.0] - 2025-02-03

### 🚀 Features

Refactoring to follow the eponymous paper published on e-print:

- drop the need for the additional label
- use AES-XTS for encryption instead of AES-GCM;
- use a memory abstraction to allow for different back-end implementation
  (present release proposes an in-memory and a Redis version);
- use an encoder abstraction to allow for different data-serialization
  strategies (present release propose a generic encoder that suits variable-,
  average-length values);

## [6.0.0] - 2023-11-21

### Features

Findex v6 implements new look following the work on the Findex formalization with @chloehebant.

In order to ease the reading, fix some vocabulary first:

- Encrypted Dictionary (EDX): a key value store which values are of constant size;
- Encrypted Multi-Map (EMM): a key value store which values are of variable size;
- Encrypted Graph (EGX): an encrypted graph which nodes contain data and pointers to other nodes;
- Encrypted Dictionary Scheme (DX-Enc): a scheme managing an EDX;
- Encrypted Multi-Map Scheme (MM-Enc): a scheme managing an EMM;
- Encrypted Graph Scheme (GX-Enc): a scheme managing an EGX;
- tag: bytes (may be a meaningful piece of information) used to point to a value in an map (H(w) in the Entry Table)
- token: _non-meaningful_ bytes used to index a value in a map (it corresponds to the UIDs)

Findex (as the product) is now composed of three algorithms:

- Findex: an index interface to hide the cryptographic details of Findex Graph;
- Findex Graph: a GX-Enc scheme using a MM-Enc scheme;
- Findex Multi-Map: a MM-Enc scheme using two DX-Enc schemes.

Two generic DX-Enc schemes are used by Findex Multi-Map:

- Entry Table: an EDX scheme in charge of storing metadata about the chains: counter, key seed (Kwi), corresponding tag (H(w_i));
- Chain Table: an EMM used to store the actual chain data; it's implementation is actually done using an EDX.

**HAS BEEN DONE**:

- [x] decide which constant to fix and which constant to use as generic (e.g. `BLOCK_LENGTH`/`LINE_LENGTH`)
- [x] add compact operation
- [x] pass all old tests
- [x] pass regression tests on database:
  - [x] add regression tests inside the repo (serialize in-memory database)
  - [x] change counter back to the hash chain
- [x] make findex types `Sync + Send`
- [x] add encryption scheme to manage encryption
- [x] update CryptoCore version
- [x] add `progress` callback (injection)
- [x] add CATS compatibility

## [5.0.3] - 2023-09-18

### Bug Fixes

- Relax `async_trait` requirements

### Features

- Support `crypto_core` v9.2.0

## [5.0.2] - 2023-09-07

### Bug Fixes

- Remove the need of nightly toolchain (use `never` and `async-trait` crates)

## [5.0.1] - 2023-09-01

### Features

- Update crypto_core to 9.1.0

## [5.0.0] - 2023-07-21

### Features

- Changed the Search, Upsert and Compact API from mutable to immutable
- Upsert now returns the set of new keywords added to the Entry Table

### Bug Fixes

- add missing `async` keyword for compact callbacks
- fix `list_removed_locations` doc

## [4.0.3] - 2023-07-11

### Features

- Use crypto_core v9.0

## [4.0.2] - 2023-06-30

### Features

- Update crypto_core to 8

### Testing

- Impl Display trait on structs used in callbacks for logging

## [4.0.1] - 2023-06-02

### Bug Fixes

- Race condition in `fetch_chains()`

## [4.0.0] - 2023-06-01

### Changed

- deletions in upsert
- format of the Chain Table (block length is now 16)
- take ownership of the data in callbacks
- allow multiple ET values in search

### Added

- add live compact functionality

## [3.1.0] - 2023-03-03

### Added

- add macro to implement Findex traits

## [3.0.0] - 2023-02-27

### Refactor

- [**breaking**] Move all interfaces (FFI, Wasm, pyo3) to `cloudproof_rust` repository
- use Kmac256 instead of Kmac128
- remove inline macros

### Testing

- Change number encoding in non regression vectors

## [2.1.0] - 2023-02-20

### Bug Fixes

- Update wasm type of progress callback

### Features

- Update `ProgressResult` serialization in ffi

## [2.0.1] - 2023-02-02

### Features

- Change `progress_callback` to return `NextKeyword` and `search` to return only `Location`

### Testing

- Add `progress_callback` tests

## [2.0.0] - 2023-01-13

### Changed

- Add `fetch_chains_batch_size` argument to search
- in `search`, `fetch_chains` calls are now run in parallel for batches of `fetch_chains_batch_size` (not working for the Java/Flutter interfaces for now)
- Improve errors

### Ci

- Replace .gitlab-ci.yml with github actions
- Test inter-languages compatibility

## [1.0.1] - 2022-12-16

### Bug Fixes

- FFI: fix serialization of returned values in `fetch_entry`
- compact: replace fetch_entry loop with call to `fetch_entry_table_uids`

## [1.0.0] - 2022-12-16

### Bug Fixes

- Add return type to FindexInternal function signature

### Documentation

- Update findex cryptographic documentation

### Features

- Only implement the callbacks required by the desired features (upsert, search, compact)
- Improve callback error message

### Miscellaneous Tasks

- Release findex v1.0

### Ci

- Add .gitlab-ci.yml

<!-- generated by git-cliff -->
