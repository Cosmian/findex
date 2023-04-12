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
|        | `10.04 us` (✅ **1.00x**)          | `90.87 us` (❌ *9.05x slower*)      | `891.55 us` (❌ *88.83x slower*)     | `9.39 ms` (❌ *935.72x slower*)        |

### upsert

|        | `Upserting 10 keyword(s)`          | `Upserting 100 keyword(s)`          | `Upserting 1000 keyword(s)`           |
|:-------|:-----------------------------------|:------------------------------------|:------------------------------------- |
|        | `185.01 us` (✅ **1.00x**)          | `1.82 ms` (❌ *9.84x slower*)        | `18.72 ms` (❌ *101.16x slower*)       |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

