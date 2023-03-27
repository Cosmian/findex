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
|        | `3.55 ms` (✅ **1.00x**)     | `3.76 ms` (✅ **1.06x slower**) | `4.43 ms` (❌ *1.25x slower*)   | `14.23 ms` (❌ *4.00x slower*)    |

### upsert

|        | `Indexing 20 keywords`          | `Indexing 200 keywords`          | `Indexing 2000 keywords`           |
|:-------|:--------------------------------|:---------------------------------|:---------------------------------- |
|        | `214.79 us` (✅ **1.00x**)       | `2.07 ms` (❌ *9.63x slower*)     | `21.45 ms` (❌ *99.85x slower*)     |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

