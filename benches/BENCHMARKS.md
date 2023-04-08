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
|        | `10.04 us` (✅ **1.00x**)          | `89.60 us` (❌ *8.92x slower*)      | `886.08 us` (❌ *88.22x slower*)     | `9.26 ms` (❌ *922.18x slower*)        |

### upsert

|        | `Upserting 10 keyword(s)`          | `Upserting 100 keyword(s)`          | `Upserting 1000 keyword(s)`           |
|:-------|:-----------------------------------|:------------------------------------|:------------------------------------- |
|        | `188.34 us` (✅ **1.00x**)          | `1.85 ms` (❌ *9.80x slower*)        | `18.66 ms` (❌ *99.06x slower*)        |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

