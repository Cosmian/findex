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

|        | `Searching 1 keyword(s)`          | `Searching 10 keyword(s)`          | `Searching 100 keyword(s)`          | `Searching 1000 keyword(s)`           |
|:-------|:----------------------------------|:-----------------------------------|:------------------------------------|:------------------------------------- |
|        | `11.07 us` (✅ **1.00x**)          | `101.23 us` (❌ *9.14x slower*)     | `1.03 ms` (❌ *92.98x slower*)       | `10.81 ms` (❌ *976.12x slower*)       |

### upsert

|        | `Upserting 10 keyword(s)`          | `Upserting 100 keyword(s)`          | `Upserting 1000 keyword(s)`           |
|:-------|:-----------------------------------|:------------------------------------|:------------------------------------- |
|        | `178.06 us` (✅ **1.00x**)          | `1.81 ms` (❌ *10.19x slower*)       | `18.49 ms` (❌ *103.83x slower*)       |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

