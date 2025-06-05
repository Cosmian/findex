# Findex Memories

A collection of memory implementations for Findex, a concurrent and database-agnostic Searchable Encryption scheme.

## Overview

Findex Memories provides "pluggable" storage backends for Findex, allowing the core Findex library to remain database-agnostic while supporting various storage systems. This separation enables users to integrate findex to their prefered database sytem.

## Available Storage Backends

This library provides implementations for the following storage systems:


| Feature | Database | Dependencies |
|---------|----------|--------------|
| `redis-mem` | Redis | [redis](https://crates.io/crates/redis) v0.31 |
| `sqlite-mem` | SQLite | [async-sqlite](https://crates.io/crates/async-sqlite) v0.4 * |
| `postgres-mem` | PostgreSQL | [tokio-postgres](https://crates.io/crates/tokio-postgres) v0.7.9<br>[tokio](https://crates.io/crates/tokio) v1.44<br>[deadpool-postgres](https://crates.io/crates/deadpool-postgres) v0.14.1 |
 

## Usage

First, add `cosmian_findex_memories` as dependency to your project :

```bash
cargo add cosmian_findex_memories # do not forget to enable the adequate feature for the backend you want to use !
```

If you don't have a running `Redis` or `Postgres` instance running, you can use the one provided on the root by running `docker-compose up`, then on your application's code :

```rust
// For Redis
use cosmian_findex_memories::postgres::RedisMemory;
use cosmian_findex::{ADDRESS_LENGTH, Findex, Address, dummy_decode, dummy_encode,WORD_LENGTH};
    
let memory = RedisMemory::<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>::connect(
    "redis://localhost:6379",
).await.unwrap();

// optionally, add the encryption layer (recommended)
// let memory = MemoryEncryptionLayer::new(&key, InMemory::default());

let findex = Findex::new(memory, dummy_encode::<WORD_LENGTH, Value>, dummy_decode);

let cat_bindings = [
    Value::try_from(1).unwrap(),
    Value::try_from(3).unwrap(),
    Value::try_from(5).unwrap(),
];

findex.insert("cat".to_string(), cat_bindings.clone()).await.unwrap();

let cat_res = findex.search(&"cat".to_string()).unwrap();

assert_eq!(
    cat_bindings.iter().cloned().collect::<HashSet<_>>(),
    cat_res
);
```

More detailed examples can be found under the [examples folder](examples).
