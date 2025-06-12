# Findex Memories

A collection of memory implementations for Findex, a concurrent and database-agnostic Searchable Encryption scheme.

## Overview

Findex Memories provides "pluggable" storage backends for Findex, allowing the core Findex library to remain database-agnostic while supporting various storage systems. This separation enables users to integrate findex to their prefered database sytem.

## Available Storage Backends

This library provides implementations for the following storage systems:

| Feature        | Database   | Dependencies                                                                                                                                                                                 |
| -------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `redis-mem`    | Redis      | [redis](https://crates.io/crates/redis) v0.31                                                                                                                                                |
| `sqlite-mem`   | SQLite     | [async-sqlite](https://crates.io/crates/async-sqlite) v0.4 \*                                                                                                                                |
| `postgres-mem` | PostgreSQL | [tokio-postgres](https://crates.io/crates/tokio-postgres) v0.7.9<br>[tokio](https://crates.io/crates/tokio) v1.44<br>[deadpool-postgres](https://crates.io/crates/deadpool-postgres) v0.14.1 |

## Usage

First, add `cosmian_findex_memories` as dependency to your project :

```bash
cargo add cosmian_findex_memories # do not forget to enable the adequate feature for the backend you want to use !
```

If you don't have a running `Redis` or `Postgres` instance running, you can use the provided [docker-compose.yml](./docker-compose.yml) file provided with this repository by running `docker-compose up`.

For detailed usage examples, refer to the [examples folder](examples).
