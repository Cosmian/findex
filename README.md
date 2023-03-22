# Findex

![Build status](https://github.com/Cosmian/findex/actions/workflows/ci.yml/badge.svg)
![Build status](https://github.com/Cosmian/findex/actions/workflows/build.yml/badge.svg)
![latest version](<https://img.shields.io/crates/v/cosmian_findex.svg>)

Findex aims to solve the following problem:

> How to securely recover the *location* of an encrypted data matching a given
> *keyword*?

It is a cryptographic protocol designed to securely make search queries on an
untrusted cloud server. Thanks to its encrypted indexes, large databases can
securely be outsourced without compromising usability.

Findex is part of Cosmian Cloudproof Encryption.

<!-- toc -->

- [Getting started](#getting-started)
- [Building and testing](#building-and-testing)
- [Findex indexes](#findex-indexes)
	- [Two indexing strategies](#two-indexing-strategies)
- [Benchmarks](#benchmarks)
- [Documentation](#documentation)

<!-- tocstop -->

## Getting started

Findex allows to index values by keywords. These values can be locations (UIDs
of an encrypted database, URLs, paths, etc.).

Using Findex API one can:
- index or desindex values by keywords via the `FindexUpsert` trait;
- search for keywords via the `FindexSearch` trait;
- compact the indexes via the `FindexCompact` trait.

These traits can be automatically implemented and a macro is provided to help
with the syntax. The default parameters (the ones used by the macro) are
defined in [`parameters.rs`](./src/parameters.rs).

Findex delegates to the user the implementation of *callbacks* to manipulate
the indexes. This makes Findex compatible with any database technology since no
database specific code is part of it. Implementation is done via the
`FindexCallbacks` trait. See [`callbacks.md`](./callbacks.md) for details on
the implementation of the callbacks.

See [`in_memory_example.rs`](./src/in_memory_example.rs) for a example of
implementation.

## Building and testing

To build Findex simply run:
```bash
cargo build --release
```

To test, run:
```bash
cargo test --release --all-features
```

To launch the benchmarks, run:
```bash
cargo bench --all-features
```

## Findex indexes

Findex relies on two server side indexes:
- **Entry Table**: provides the values needed to fetch the correct locations
  from the Chain Table. Each indexing keyword matches a line in the Entry
  Table.
- **Chain Table**: securely stores the indexed values. These indexed values may
  be locations or pointers to other keywords. Locations usually are database
  UIDs, but Findex can be used to index any kind of location (URL, path...). In
  order to make lines indistinguishable, the variable length indexed values are
  stored by blocks of fixed length and the same number of blocks is stored in
  each line (padding is added where necessary).

Findex indexes are key value stores which structure is given in the following
tables, with $K_{w_i}$ the ephemeral key associated to a keyword $w_i$,
$H_{w_i}$ the hash of $w_i$ and $UID_{last}$ the last UID of the chain of
indexed values associated to $w_i$.

<table>
	<tr>
		<th colspan=4>Entry Table</th>
	</tr>
	<tr>
		<th>key</th>
		<th colspan=3>value</th>
	</tr>
	<tr>
		<td>UID</td>
		<td>$K_{w_i}$</td>
		<td>$H_{w_i}$</td>
		<td>$UID_{last}$</td>
	</tr>
</table>

<table>
	<tr>
		<th colspan=4>Chain Table</th>
	<tr>
	<tr>
		<th>key</th>
		<th colspan=3>value</th>
	</tr>
	<tr>
		<td>UID</td>
		<td>$\textnormal{block}_1$</td>
		<td>...</td>
		<td>$\textnormal{block}_B$</td>
	</tr>
</table>

The Chain Table values are serialized as follows (sizes are given in bytes):

<table>
	<tr>
		<th rowspan=2></th>
		<th rowspan=2>flag</th>
		<th colspan=2>Block<sub>1</sub></th>
		<th>...</th>
		<th colspan=2>Block<sub>B</sub></th>
	</tr>
	<tr>
		<th>prefix</th>
		<th>data</th>
		<th>...</th>
		<th>prefix</th>
		<th>data</th>
	</tr>
	<tr>
		<th>Size (in bytes)</th>
		<td>1</td>
		<td>1</td>
		<td>16</td>
		<td>...</td>
		<td>1</td>
		<td>16</td>
	</tr>
</table>

When stored, the values of the indexes are symmetrically encrypted with an
AEAD. Our implementation uses a 16-bytes MAC tag and a 12-bytes nonce.

The flag is used to mark the blocks as being addition or deletions. Each bit
corresponds to a block, which limits the possible number of blocks inside a
single Chain Table value to 8. The prefix is used to write the actual length of
the data stored inside a block.

Therefore:
- given $N$ the number of keywords used, the size of the Entry Table is given
  by (in bytes):
```math
L_{entry~table} = (L_{uid} + C_e + L_{K_{w_i}} + L_{H_{w_i}} + L_{uid}) \cdot N
       		= 140 \cdot N
```
- given $V(w_i)$ the volume of the keyword $w_i$ (i.e. the number of values
  indexed by this keyword) the size of the Chain Table is given by (in bytes):
```math
L_{chain~table} = \left(L_{uid} + C_e + 1 + B * (1 + L_{block})\right) \sum\limits_{i~\in~[1,N]}\left\lceil \frac{V(w_i)}{B}\right\rceil
                = 146 \sum\limits_{i~\in~[1;N]}\left\lceil \frac{V(w_i)}{B}\right\rceil
```
where:
- the length of an UID: $L_{uid} = 32~\textnormal{bytes}$
- the length of the ephemeral key: $K_{w_i} = 16~\textnormal{bytes}$
- the length of the hash of the keyword: $H_{w_i} = 32~\textnormal{bytes}$
- the Chain Table width: $B = 5$
- the block length: $L_{block} = 16~\textnormal{bytes}$
- the encryption overhead: $C_e = 28~\textnormal{bytes}$

### Two indexing strategies

Naive (locations are indexed for all possible slices):

- `mar` -> {locations}
- `mart` -> {locations}
- `marti` -> {locations}
- `martin` -> {locations}
- `martine` -> {locations}

Graph:

- `mar` -> `mart`
- `mart` -> `marti`
- `marti` -> `martin`
- `martin` -> `martine`
- `martine` -> {locations}

Disadvantage of graphs: more interactions between client and server: 4 average
compared to 1 for the naive solution.

Advantage of graphs: optimal storage of the locations info since they are not
repeated in the chain table.

| Avg locations | #records graphs | #records naive | ratio | size (kb) graphs | size (kb) naive | ratio |
|---------------|-----------------|----------------|-------|------------------|-----------------|-------|
| 1             | 86018           | 86018          | 1.00  | 5605             | 5704            | 1.01  |
| 2             | 105966          | 172036         | 1.62  | 6994             | 11745           | 1.68  |
| 3             | 125914          | 258054         | 2.04  | 8344             | 17618           | 2.11  |
| 4             | 145862          | 244072         | 2.35  | 9694             | 23491           | 2.42  |
| 5             | 165810          | 430090         | 2.59  | 11044            | 29364           | 2.65  |

### Benchmarks

The benchmarks presented in this section are run on a Intel(R) Xeon(R) Platinum 8171M CPU @ 2.60GHz.

- [Findex in memory (no database)](./benches/BENCHMARKS.md)

## Documentation

Findex supporting paper can be found [Findex.pdf](./documentation/Findex.pdf).
Documentation on callback implementation details can be found in
[`callbacks.md`](./callbacks.md).

The developer documentation can be found on [doc.rs](https://docs.rs/cosmian_findex/latest/cosmian_findex/index.html)
