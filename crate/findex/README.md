# Findex

To build Findex simply run:

```bash
cargo build --release
```

To test, run:

```bash
cargo test --release --all-features
```

To launch the benchmarks, run:

```bash
cargo bench --all-features
```

Note that benches are quite involving and require *several hours* for a full
run. Once all benchmarks are run, you will find detailed reports under `target/criterion`.
findex
