# Benchmarks

## Table of Contents

- [Overview](#overview)
- [Benchmark Results](#benchmark-results)
  - [search](#search)
  - [upsert](#upsert)

## Overview

This is a benchmark comparison report.

## Benchmark Results

### search

|        | `Searching 1 word`          | `Searching 10 words`           | `Searching 100 words`          | `Searching 1000 words`           |
|:-------|:----------------------------|:-------------------------------|:-------------------------------|:-------------------------------- |
|        | `6.18 ms` (✅ **1.00x**)     | `5.75 ms` (✅ **1.07x faster**) | `6.85 ms` (✅ **1.11x slower**) | `15.05 ms` (*2.43x slower*)    |

### upsert

|        | `Indexing 20 keywords`          | `Indexing 200 keywords`          | `Indexing 2000 keywords`           |
|:-------|:--------------------------------|:---------------------------------|:---------------------------------- |
|        | `186.15 us` (✅ **1.00x**)       | `1.71 ms` (*9.20x slower*)     | `17.79 ms` (*95.57x slower*)     |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)
