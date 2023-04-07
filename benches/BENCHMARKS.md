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
|        | `3.86 ms` (✅ **1.00x**)     | `4.03 ms` (✅ **1.05x slower**) | `4.95 ms` (❌ *1.28x slower*)   | `13.74 ms` (❌ *3.56x slower*)    |

### upsert

|        | `Indexing 20 keywords`          | `Indexing 200 keywords`          | `Indexing 2000 keywords`           |
|:-------|:--------------------------------|:---------------------------------|:---------------------------------- |
|        | `189.25 us` (✅ **1.00x**)       | `1.85 ms` (❌ *9.80x slower*)     | `18.59 ms` (❌ *98.23x slower*)     |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

