# Findex

This crate provides the core functionality of Findex, defining the abstract data types, cryptographic operations, and encoding algorithms.

Findex also supports batch operations, allowing to index and search multiple items in a single request. This feature improves performance and efficiency when network time is a bottleneck.

## Setup

Add `cosmian_findex` as dependency to your project :

```toml
[dependencies]
cosmian_findex = "8.0.0"
```

An usage example is available in the [examples folder](./examples).
