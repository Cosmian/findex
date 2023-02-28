#!/bin/sh

set -e

# Usage: bash generate.sh

cargo install cargo-criterion
cargo install criterion-table

cargo criterion --message-format=json | criterion-table >benches/BENCHMARKS.md

sed -i "s/❌ //g" benches/BENCHMARKS*.md
sed -i "s/🚀 //g" benches/BENCHMARKS*.md
# sed -i "s/✅ //g" benches/BENCHMARKS*.md
