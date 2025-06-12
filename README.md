# Findex: Symmetric Searchable Encryption

[![Crates.io](https://img.shields.io/crates/v/cosmian_findex.svg)](https://crates.io/crates/cosmian_findex)
[![Documentation](https://docs.rs/cosmian_findex/badge.svg)](https://docs.rs/cosmian_findex)
[![License](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)

Findex is a Symmetric Searchable Encryption (SSE) library that enables encrypted search over encrypted data. It allows you to securely index and search encrypted data without compromising privacy or security.

## Architecture

This repository is organized as a Rust workspace with two crates:

- `cosmian_findex`: Core library implementing the SSE algorithms
- `cosmian_findex_memories`: Storage backend implementations for different databases

## Installation

Add `cosmian_findex` to your Cargo.toml:

```toml
[dependencies]
cosmian_findex = "8.0.0"
# Optional - include backend implementations
cosmian_findex_memories = { version = "8.0.0", features = ["redis-mem", "sqlite-mem", "postgres-mem"] }
```

## Related Projects

[Findex Server](github.com/cosmian/findex-server) - A production-ready Findex server implementation

## License

This project is licensed under the Business Source License 1.1 (BUSL-1.1).
