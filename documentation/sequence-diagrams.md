# Findex sequence diagrams

This documents describes the Findex operations using sequence diagrams. Refer
to the [functional documentation](functional.md) in order to understand the
roles of the different participants.

## Search

```mermaid
sequenceDiagram
    actor User

    User->>+Findex: search(key, label, { keyword })

    Findex->>+ET: fetch({ token })
    ET->>-Findex: [ (token, value) ]

    Findex->>+CT: fetch({ token })
    CT->>-Findex: { (token, value) }

    Findex->>-User: { keyword: { data } }
```

## Add/Delete

```mermaid
sequenceDiagram
    actor User

    User->>+Findex: add/delete(..., { data: {keyword} })

    Findex->>+ET: fetch({ token })
    ET->>-Findex: return [ (token, value) ]

    loop while upsert returns a non-empty set
        Findex->>+ET: upsert({ token->old_value }, { token->new_value })
        ET->>-Findex: return { token->current_value }
    end

    Findex->>+CT: insert({ token->value })
    CT->>-Findex: return

    Findex->>-User: return { keyword }
```

## Compact

```mermaid
sequenceDiagram
    actor User

    User->>+Findex: compact(...)

    Findex->>+ET: dump_tokens()
    ET->>-Findex: return { token }

    loop by batch of ET tokens
        Findex->>+ET: fetch({ token })
        ET->>-Findex: return { token->value }

        Findex->>+CT: fetch({ token })
        CT->>-Findex: return { token->value }

        par
            Findex->>+CT: insert({ token->value })
            CT->>-Findex: return
        and
            Findex->>+ET: insert({ token->value })
            ET->>-Findex: return
        end

        par
            Findex->>+ET: delete({ token })
            ET->>-Findex: return
        and
            Findex->>+CT: delete({ token })
            CT->>-Findex: return
        end
    end

    Findex->>-User: return
```
