GLOSSARY
========

## Naming conventions

- Index: a listing of keys associated to some data.

- Keyword: arbitrary value used as index key.

- Association: couple composed by a keyword and a data. Searching for a keyword
  should return all data associated to it.

- Chain Table: an encrypted dictionary storing the data associated to each
  indexed keywords.

- Link: nickname for an Chain Table value.

- Chain: sequence of all the links containing data associated to the same
  keyword.

<!--
   -  It is important to underline that the use of this name implies the existence
   -  of a specific *order* between the links. Thus a set of links is not a chain
   -  as a set does not enforce any specific order between the links.
   -
   -  In practice, the order among chain links matters since the `delete` operation
   -  adds negated data to the chains, which invalidates all previous occurrences,
   -  but not subsequent occurrences of this data.
   -->

- Entry Table: table storing the metadata of the list of values indexed for a
  given keyword.

- Entry: nickname for an Entry Table value.

## Cryptographic definitions

- Tag: arbitrary value used as dictionary key.

- Token: cryptographic hash of a tag, used as key in an encrypted dictionary.

- Dictionary: map from a set of tags to a set of values, each tag being
  associated to a unique value; a dictionary thus encodes a bijection from a
  set of tags to a set of values.

- Multi-map: map from a set of tags to a set of values, each tag being
  associated to several values.

- Dictionary Encryption scheme (DX-Enc): scheme allowing to securely manage
  requests on an encrypted dictionary.

- Multi-Map Encryption scheme (MM-Enc): scheme allowing to securely manage
  requests on an encrypted multi-map.

- Graph Encryption scheme (GX-Enc): scheme allowing to securely manage requests
  on an encrypted graph.
