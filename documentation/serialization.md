# Findex tables serialization

This page describes the format in which the data is actually stored inside the
Entry and Chain tables.

Both the Entry Table and the Chain Table represent a key/value store. Each key
(subsequently called `token`) is the result of a cryptographic hash function
and is therefore sufficiently secure. The values however need to be encrypted
before being sent for storage to the backend.

Therefore, the actual structures stored are:

```txt
{
    (token) [u8; 32]: (nonce) [u8; 12]
                        || (ciphertext) [u8; PLAINTEXT_LENGTH]
                        || (mac) [u8; 16],
    ...
}
```

Where the ciphertext is the results of the AES256-GCM encryption of the
plaintext value. This structure is therefore serialized to a couple composed by
a `32`-bytes value and a `28+PLAINTEXT_LENGTH` value.


## Serialization of the Entry Table values

The Entry Table is the simplest table. It stores the metadata of the chains of
each keyword. Its values are therefore:

```txt
(entry) {
    last_link_token: [u8; 32],
    seed: [u8; 16],
    keyword_hash: [u8; 32],
}
```

Which are therefore serialized into 80-bytes values, and the encrypted value is
thus 108-bytes long.

## Serialization of the Chain Table values

The Chain Table stores the list of data associated each keyword in a chain of
values called links. All stored data are padded into 16-bytes `blocks`. The
last block may be padded with zeros. Blocks are then grouped into 5-blocks
values. The last value may be padded with empty blocks.

Additional bytes are needed in the serialization to store information about the
blocks (resulting in one-byte block flags) and another block is needed per
value to store the sign of the data stored in each block (`add` inserts raw
data while `delete` inserts negated data).

```txt
(link) {
    flag: u8,
    blocks: [ (block) { flag: u8, data: [u8; 16] }; 5 ]
}
```

This structure is therefore serialized to a 86-bytes value and the resulting
encrypted value is thus 114-bytes long.
