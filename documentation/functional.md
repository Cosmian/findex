Findex functional documentation
===============================

## How to securely manage an index

This documents describes in details the functionalities of Findex.

The goal of Findex is to allow users to securely manage an index. To know more
about the security guarantees of Findex, see the [security
documentation](security.md).

### An index as a graph

An index can be thought of as a graph: each indexed keyword is associated a
node, which contains all data indexed under this keyword; some of this data can
be other keywords which can be represented as directed edges linking the
vertices of each one of the associated keywords.

```mermaid
classDiagram
    Martine <|-- Martin
    Martin  <|-- Marti
    Marti   <|-- Mart
    Marth   <|-- Mart
    Martha  <|-- Marth
    Marthe  <|-- Marth
    Mart    <|-- Mar

    class Martin {
        Martin's data
    }
    class Martine {
        Martine's data
    }
    class Martha {
        Martha's data
    }
    class Marthe {
        Marthe's data
    }
```

### An index as a multi-map

The graph presented above can also be seen as a multi-map, storing the list of
indexed values associated to each keyword. These indexed values can either be
an associated data or an associated keyword. It is possible to retrieve the
results stored in the graph by iteratively searching for keywords: all
associated keywords found during a search are fed to the new search iteration.

```txt
{
    'Mar': { Keyword('Mart') },
    'Mart': {
        Keyword('Marth'),
        Keyword('Marti'),
    },
    'Marth': {
        Keyword('Martha'),
        Keyword('Marthe'),
    },
    'Marti': { Keyword('Marthin') },
    'Martha': { Data("Martha's data") },
    'Marthe': { Data("Marthe's data") },
    'Martin': {
        Keyword('Martine'),
        Data("Martin's data"),
    },
    'Martine': { Data("Martine's data") },
}
```

The issue with this structure is that it is not secure enough (even when
encrypted, the number of results is apparent and could allow distinguishing
some keywords).

### An index as a couple of dictionaries

Each multi-map value can be split into values of equal sizes called links, as
described in the [serialization](serialization.md) documentation. The sequence
of links that is generated from a given multi-map value is called a chain. This
allows representing the multi-map using two dictionary encryption schemes:
- the first DX-Enc is called *Chain Table*: it contains all the chains
  generated from all the multi-map values.
- the second DX-Enc is called *Entry Table*: it contains for each keyword all
  the metadata needed to retrieve the entire chain from the Chain Table.

The role of Findex is therefore to transform [index](../src/index/mod.rs#33)
requests into [DX-Enc](../src/edx/mod.rs#30) requests, without leaking
information.

## A generic construction

Findex implementation is generic over the practical implementation of the
DX-Enc used to represent the Entry and the Chain tables. In practice, an
implementation is provided but it uses a generic backend interface used to
abstract the storage technology used. This allows users to use Findex on top of
any database.
