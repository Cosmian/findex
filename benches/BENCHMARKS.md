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
|        | `4.65 ms` (✅ **1.00x**)     | `5.03 ms` (✅ **1.08x slower**) | `6.41 ms` (❌ *1.38x slower*)   | `15.97 ms` (❌ *3.44x slower*)    |

### upsert

|        | `Indexing 20 keywords`          | `Indexing 200 keywords`          | `Indexing 2000 keywords`           |
|:-------|:--------------------------------|:---------------------------------|:---------------------------------- |
|        | `214.88 us` (✅ **1.00x**)       | `2.06 ms` (❌ *9.60x slower*)     | `21.32 ms` (❌ *99.21x slower*)     |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

