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
|        | `7.26 us` (✅ **1.00x**)           | `60.26 us` (❌ *8.31x slower*)      | `597.19 us` (❌ *82.31x slower*)     | `6.02 ms` (❌ *829.65x slower*)        |

### upsert

|        | `Upserting 10 keyword(s)`          | `Upserting 100 keyword(s)`          | `Upserting 1000 keyword(s)`           |
|:-------|:-----------------------------------|:------------------------------------|:------------------------------------- |
|        | `113.48 us` (✅ **1.00x**)          | `1.12 ms` (❌ *9.87x slower*)        | `11.51 ms` (❌ *101.42x slower*)       |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)
