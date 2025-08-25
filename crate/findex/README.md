# Findex

Symmetric Searchable Encryption (SSE) scheme are cryptographic tools allowing to
use offloaded indexes with control leakages. Developed at Cosmian, Findex is the
first SSE scheme that provides efficient wait-free search and lock-free insert
operations while remaining entirely independent from the server implementation.
The former guarantees good performances in presence of concurrent queries to the
index while the later, often overlooked in theoretical publications, is of high
practical interest since it allows using state-of-the-art databases like
PostgreSQL and Redis to save the index instead of rolling out our own DBMS
implementation. The reference documentation for the Findex algorithm along with
formal security claims and benchmarks can be found
[here](https://eprint.iacr.org/2024/1541.pdf).
