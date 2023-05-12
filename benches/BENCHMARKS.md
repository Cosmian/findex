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
|        | `11.18 us` (✅ **1.00x**)          | `99.07 us` (❌ *8.86x slower*)      | `1.01 ms` (❌ *90.42x slower*)       | `10.85 ms` (❌ *970.72x slower*)       |

### upsert

|        | `Upserting 10 keyword(s)`          | `Upserting 100 keyword(s)`          | `Upserting 1000 keyword(s)`           |
|:-------|:-----------------------------------|:------------------------------------|:------------------------------------- |
|        | `180.68 us` (✅ **1.00x**)          | `1.80 ms` (❌ *9.95x slower*)        | `18.24 ms` (❌ *100.95x slower*)       |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)
