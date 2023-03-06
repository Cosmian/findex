#!/bin/sh
# Usage: bash generate.sh

set -e

cargo install cargo-criterion
cargo install criterion-table

cargo criterion --features in_memory --message-format=json | criterion-table >benches/BENCHMARKS.md

sed -i "s/❌ //g" benches/BENCHMARKS*.md
sed -i "s/🚀 //g" benches/BENCHMARKS*.md
