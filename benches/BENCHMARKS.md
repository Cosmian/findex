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
|        | `3.89 ms` (✅ **1.00x**)     | `3.96 ms` (✅ **1.02x slower**) | `4.92 ms` (❌ *1.26x slower*)   | `13.27 ms` (❌ *3.41x slower*)    |

### upsert

|        | `Indexing 20 keywords`          | `Indexing 200 keywords`          | `Indexing 2000 keywords`           |
|:-------|:--------------------------------|:---------------------------------|:---------------------------------- |
|        | `178.15 us` (✅ **1.00x**)       | `1.80 ms` (❌ *10.10x slower*)    | `18.48 ms` (❌ *103.75x slower*)    |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

