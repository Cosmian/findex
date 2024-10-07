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

Note that benches are quite involving and require *several ours* for a full
run. Once all benchmarks are run, one can reproduce our figure by replacing the
data in the `.dat` files in `benches/data/` and compiling the latex script
`benches/make_figures.tex`.
