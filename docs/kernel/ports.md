# Ports

**Protocols the host implements.** The kernel defines them and imports nothing.

## Why ports rather than base classes

The constraint that forced this design: across surveyed codebases, the same conceptual table
had genuinely diverged.

```
   AgentRun across four codebases
   ─────────────────────────────────────────────────────────────────
   table       ai_engine_agent_runs │ lumo_ai_agent_runs │ agent_runs
   tokens      input_/output_       │ input_/output_     │ prompt_/completion_
   governance  (absent)             │ decision_reason    │ governance_reason
   user FK     yes + shared_with    │ no                 │ no
   migrations  15                   │ 6                  │ 2
```

A framework that mandates its own table cannot be adopted by any of them without a migration
merge against live production data. So it mandates nothing.

```
   MANDATED MODEL                      PORT
   ─────────────────────               ────────────────────────────
   framework owns the table            host implements a protocol
   adoption = migration merge          adoption = write an adapter
   big bang, all or nothing            incremental, reversible
```

A host can adopt the gateway alone, against its existing tables, and leave its agents
untouched.

## The ports

```
   STORAGE
     RunStore          persist and fetch attestations
     AuditSink         append events; MUST be append-only
     PolicyStore       autonomy policy rows
     ApprovalStore     pending action lifecycle
     MemoryStore       scoped, erasable recall

   MODEL
     LLMProvider       completions
     Embedder          vectors

   RETRIEVAL
     Retriever         fetch candidate evidence
     Reranker          reorder candidates

   INFRASTRUCTURE
     CacheBackend      exact + semantic cache
     Clock             time; injected for determinism
     IdGenerator       run ids; seeded for replay
```

## Contract obligations

Some ports carry requirements a type signature cannot express. These are documented, and the
conformance kit tests them.

```
 ┌───────────────┬──────────────────────────────────────────────────────┐
 │ AuditSink     │ append-only. Enforce below the application — a       │
 │               │ trigger or equivalent, not a convention.             │
 │ RunStore      │ attestations are immutable once written. Corrections │
 │               │ are new records referencing the old.                 │
 │ Retriever     │ MUST scope by tenant at the query, not after.        │
 │ Clock         │ monotonic within a run.                              │
 │ MemoryStore   │ MUST support deletion by subject (erasure requests). │
 │ ApprovalStore │ MUST expire pending actions; no open-ended holds.    │
 └───────────────┴──────────────────────────────────────────────────────┘
```

The `Retriever` obligation is the highest-severity one. Scoping after retrieval means the
index was already queried across tenants, and a scoring bug becomes a data leak.

## Shape

```python
class RunStore(Protocol):
    def create(self, att: Attestation) -> RunId: ...
    def get(self, run_id: RunId) -> Attestation | None: ...
    def supersede(self, run_id: RunId, att: Attestation) -> RunId: ...


class AuditSink(Protocol):
    def append(self, event: AuditEvent) -> None: ...
    def read_chain(self, run_id: RunId) -> Sequence[AuditEvent]: ...
```

Note `supersede` rather than `update`. Attestations are immutable; a correction is a new
record pointing at what it replaces. That preserves the original for anyone who relied on it.

## Adapters

The Django adapter ships default implementations of every port, with models and migrations,
for greenfield projects. They are **offered, never required** — which is what makes
incremental adoption possible for the codebases that already have their own tables.

## Related

- [`config.md`](config.md) — what else is injected
- [`determinism.md`](determinism.md) — `Clock`, `IdGenerator`
- [`../adapters/django.md`](../adapters/django.md) — the default implementations
