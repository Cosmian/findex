# Findex

This crate provides the core functionality of Findex, defining the abstract data types, cryptographic operations, and encoding algorithms.

Findex also supports batching operations into a singe call to the memory interface, which reduces connection overhead and avoids file descriptor limits on some Linux systems.

## Setup

Add `cosmian_findex` as dependency to your project :

```toml
[dependencies]
cosmian_findex = "8.0.1"
```

An usage example is available in the [examples folder](./examples).
