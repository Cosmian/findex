Findex security
===============

*Note*: This page is a work in progress.

For an in-depth analysis of Findex security guaranties, and a more formal
approach of security definitions and leakage, see Findex
[whitepaper][whitepaper].

## Snapshot security

The snapshot security means that no information is leaked if an attacker
succeeds in dumping the database storing the Findex indexes.

Findex aims to provide the snapshot security level (the proof is a work in
progress).

The index stored is composed of:
- tokens (UIDs) that are the result of a cryptographic hash function with at
  least 256 bits of security;
- encrypted values produced using AES256-GCM.

As such, it provides 256 bits of classic security and 128 bits of post-quantum
security against decryption and brute-force attack on the tokens. The indexed
values (stored in the Chain Table values) are therefore secured.

Another security concept is the *volume*. It describes the number of data
associated to a given keyword.

Since the data associated to each keyword are stored inside constant-size
values in the Chain Table and that the security levels listed above prevent
attackers from grouping these values per keyword, the index stored does not
leak the volume.

## Multi-snapshot security

The multi-snapshot security means that no information is leaked if an attacker
succeeds in dumping the database storing the Findex indexes *several times*
(possibly an infinite amount of times, at any rate).

Findex may provide the multi-snapshot security (work in progress).

## Known leaks

We are trying hard to make Findex as safe as possible. However, security has a
cost and everything comes down to trading security guarantees for performance.
Findex aims at providing a state-of-the-art balance between security guarantees
and performances.

The following section introduces the main known Findex leaks, justifies
introducing these leaks and ways to mitigate them whenever possible.

### Findex operations distinguishness

Findex cannot hide the nature of ongoing operations: the server learns what
incoming requests are (one of the backend interface methods) and by associating
several such requests, differentiate search operations from modification (adds
or deletes) from compact operations.

This leak can be mitigated by making user connections *concurrent* and
*indistinguishable*. That way, it makes is much more difficult for the server
to group backend requests by Findex operation.

*Note*: due to their implementation, add and delete operations are
indistinguishable (a delete adds negated values and is therefore an add).

### Search pattern leakage

The search pattern is the information about the equality of the underlying
keyword of two given database accesses. Leaking the search access implies that
an attacker is able to count the number of times any unknown keyword has been
called. In their simplest form, attacks on this leakage compare the access
frequency distribution of the unknown keywords with a known frequency
distribution on known keywords from a similar context to deduce the identity of
the unknown accessed keywords.

Therefore, leaking search pattern may leak the identity of the keywords stored
in the index and the identity of the keywords requested by the clients.

Like all SSE, Findex leaks the *search pattern*. It has been proven that in
order to hide the search pattern, a logarithmic bandwidth overhead on the
communication between the client and the server is unavoidable. The
state-of-the-art construction that preserve search pattern privacy is the ORAM.

Since a logarithmic communication bandwidth overhead cost is prohibitively high
for several applications, we chose not to base Findex on an ORAM construction
and to leak the search pattern.

However, we provide a way to "shuffle" the index, that can be used to reset the
knowledge gained by the server over the time: the compact operation.

<!--
   -# References
   -->

[whitepaper]: ./whitepaper.pdf "Findex whitepaper"
