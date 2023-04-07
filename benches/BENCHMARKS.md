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
|        | `4.80 ms` (✅ **1.00x**)     | `4.64 ms` (✅ **1.04x faster**) | `5.81 ms` (❌ *1.21x slower*)   | `14.65 ms` (❌ *3.05x slower*)    |

### upsert

|        | `Indexing 20 keywords`          | `Indexing 200 keywords`          | `Indexing 2000 keywords`           |
|:-------|:--------------------------------|:---------------------------------|:---------------------------------- |
|        | `184.36 us` (✅ **1.00x**)       | `1.73 ms` (❌ *9.38x slower*)     | `17.93 ms` (❌ *97.23x slower*)     |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

