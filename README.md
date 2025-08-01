# Findex: Symmetric Searchable Encryption

[![Crates.io](https://img.shields.io/crates/v/cosmian_findex.svg)](https://crates.io/crates/cosmian_findex)
[![Documentation](https://docs.rs/cosmian_findex/badge.svg)](https://docs.rs/cosmian_findex)
[![License](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)

Findex is a Symmetric Searchable Encryption (SSE) library that enables encrypted search over encrypted data. It allows you to securely index and search encrypted data without compromising privacy or security.

## Architecture

This repository is organized as a Rust workspace with two crates:

- `cosmian_findex`: Core library implementing the SSE algorithms
- `cosmian_sse_memories`: Storage back-end implementations for different databases

## Related Projects

[Findex Server](github.com/cosmian/findex-server) - A production-ready Findex server implementation

## License

This project is licensed under the Business Source License 1.1 (BUSL-1.1).
