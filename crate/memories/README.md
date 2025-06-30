# Findex Memories

A collection of memory implementations for Findex, a concurrent and database-agnostic Searchable Encryption scheme.
Findex memories provide compatibility with concrete databases, allowing the core Findex library to remain database-agnostic. This separation enables users to integrate Findex with their preferred database system.

## Setup

First, add `cosmian_findex_memories` as dependency to your project :

```bash
cargo add cosmian_findex_memories # do not forget to enable the adequate feature for the back end you want to use !
```

If you don't have a running `Redis` or `Postgres` instance running, you can use the [`docker-compose.yml`](./docker-compose.yml) file provided with this repository by running `docker-compose up`.

For detailed usage examples, refer to the [examples folder](examples).

## Available Storage Back-ends

This library provides implementations for the following storage systems:

| Feature        | Database   | Dependencies                                                                                                                                                                                 |
| -------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `redis-mem`    | Redis      | [redis](https://crates.io/crates/redis) v0.31                                                                                                                                                |
| `sqlite-mem`   | SQLite     | [async-sqlite](https://crates.io/crates/async-sqlite) v0.5                                                                                                                                   |
| `postgres-mem` | PostgreSQL | [tokio-postgres](https://crates.io/crates/tokio-postgres) v0.7.9<br>[tokio](https://crates.io/crates/tokio) v1.44<br>[deadpool-postgres](https://crates.io/crates/deadpool-postgres) v0.14.1 |

To execute the PostgreSQL tests and run the benches locally with your postgres installation, the easiest way would be to add the following service to your pg_service.conf file (usually under `~/.pg_service.conf`):

```toml
[cosmian_service]
host=localhost
dbname=cosmian
user=cosmian
password=cosmian
```
