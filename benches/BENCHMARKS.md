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
|        | `9.91 us` (✅ **1.00x**)           | `92.17 us` (❌ *9.30x slower*)      | `891.96 us` (❌ *89.99x slower*)     | `9.54 ms` (❌ *962.30x slower*)        |

### upsert

|        | `Upserting 10 keyword(s)`          | `Upserting 100 keyword(s)`          | `Upserting 1000 keyword(s)`           |
|:-------|:-----------------------------------|:------------------------------------|:------------------------------------- |
|        | `181.31 us` (✅ **1.00x**)          | `1.76 ms` (❌ *9.70x slower*)        | `19.09 ms` (❌ *105.31x slower*)       |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

