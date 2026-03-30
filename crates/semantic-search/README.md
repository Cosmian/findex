# Semantic Search

## Storage Back-ends

If you don't have a running `Postgres` instance running, you can use the [`docker-compose.yml`](./docker-compose.yml) file provided with the memories repository by running `docker-compose up`.

## Simple demo

In `semantic-search` folder, `cargo build`

You can use the `vec1.json` file to:
- insert a vector with `./target/debug/cosmian-semantic-search insert --data 'vec1' --vector-file crates/semantic-search/vec1.json`
- query a vector with `./target/debug/cosmian-semantic-search query --vector-file crates/semantic-search/vec1.json --k 2`

You can also directly pass the vector instead of a file.

## Running examples

There are two examples in `python_client.py` that you can run:
- `python3 crates/semantic-search/python_client.py demo 5`
- `python3 crates/semantic-search/python_client.py demo2 "How long sleep a cat per day?"`