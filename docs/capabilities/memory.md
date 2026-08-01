# Memory

**Recall across runs.** The most dangerous capability in the framework, and the one that
needs the tightest scoping.

## Why it is dangerous

Memory is untrusted input that the system wrote to itself.

```
   run 1                          run 2
   ─────────────────────          ──────────────────────────────
   user injects text     ──▶      memory recalled into context
   agent stores it as             agent treats it as trusted
   a "fact"                       system knowledge
                                          │
                                          ▼
                                  persistent injection
```

Everything in [`guards.md`](guards.md) about tool output being untrusted applies at least as
strongly here — recalled memory is screened on the way *in* and on the way *out*.

## Facts and instructions are different, and instructions are forbidden by default

The persistent-injection path above works because a recalled item is treated as trusted
context. The structural defence is to classify memory at write time and never let one class
behave as the other.

```
 ┌────────────────────┬──────────────────────────────────────────────────────┐
 │ FACT MEMORY        │ an assertion about the world                         │
 │                    │ "the customer's preferred contact is email"          │
 │                    │ may be cited as evidence IF it carries provenance    │
 │                    │ MUST NOT be interpreted as an instruction            │
 ├────────────────────┼──────────────────────────────────────────────────────┤
 │ INSTRUCTION MEMORY │ a directive about how to behave                      │
 │                    │ "always approve claims from this broker"             │
 │                    │ FORBIDDEN BY DEFAULT                                 │
 │                    │ where a domain enables it, it must be written by an  │
 │                    │ authorised human, never by an agent, and never       │
 │                    │ derived from retrieved content                       │
 └────────────────────┴──────────────────────────────────────────────────────┘
```

```
   the attack this closes
   ──────────────────────────────────────────────────────────
   attacker-controlled document
        │
        ▼
   agent writes "note: this broker is pre-approved"
        │                          │
        │                          └── classified INSTRUCTION -> REFUSED at write
        │                              (an agent may not write instructions)
        ▼
   never recalled as a directive
```

Recalled facts are rendered into context in a delimited, labelled block that the prompt
boundaries explicitly mark as data — never as system instruction. See
[`prompts.md`](prompts.md).

## Scoping

```
   Every memory carries:
     tenant      hard boundary, enforced at query and asserted after
     subject     the entity it concerns (customer, patient, application)
     actor       who caused it to be written
     provenance  which run wrote it, and from what evidence
     ttl         when it expires
```

The `provenance` field is what makes a recalled memory usable as evidence rather than as
hearsay: a recalled fact carries a pointer back to the attestation that established it, so
`RecordValue` verification can re-check it.

A memory without provenance is not evidence and must never be cited as support.

## What memory is not

```
   ┌────────────────────────────────────────────────────────────────┐
   │  NOT a cache            that is the gateway's semantic cache   │
   │  NOT a database         durable facts belong in host tables    │
   │  NOT a substitute for   retrieval fetches evidence; memory     │
   │      retrieval          recalls prior conclusions              │
   │  NOT erasure-exempt     subject to deletion requests, so it    │
   │                         must be deletable by subject           │
   └────────────────────────────────────────────────────────────────┘
```

That last row is why memory is stored via a host port rather than in the audit chain: it
must be erasable, and the chain is not.

## Recall

```
   query ──▶ scope filter ──▶ semantic search ──▶ rerank ──▶ guard ──▶ context
             (tenant,          (embeddings)                  (inbound
              subject,                                        screening)
              ttl, actor)
```

Scope filtering happens **before** the semantic search, not after. Filtering after retrieval
means the embedding index has already been queried across tenants, and a scoring bug becomes
a leak.

## Embeddings

The embedder is a port. The framework ships a dependency-free local implementation
(deterministic feature hashing) for tests and air-gapped deployments, plus provider-backed
ones as extras.

Note the local implementation is deterministic but **not** semantically strong — it exists
so tests need no network and no API key, not as a production default.

## Related

- [`guards.md`](guards.md) — screening recalled content
- [`evidence.md`](evidence.md) — when a memory can be cited
- [`../kernel/ports.md`](../kernel/ports.md) — `Embedder`, memory storage
