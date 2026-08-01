# Audit — the provenance warrant

**What happened, in what order, and can the record be forged?**

## Why a hash chain rather than a log table

An ordinary audit table answers "what does the database say happened." A regulator's
question is stricter: "can you show the record was not edited afterwards?"

```
   PLAIN AUDIT TABLE                  HASH-CHAINED EVENTS
   ─────────────────────              ────────────────────────────────
   id | ts | actor | action           each event carries the hash of
                                      its predecessor:
   Anyone with UPDATE can
   rewrite history. Anyone            e1.hash = H(e1.payload || "")
   with DELETE can remove it.         e2.hash = H(e2.payload || e1.hash)
   Nothing detects either.            e3.hash = H(e3.payload || e2.hash)

                                      Edit e2 -> e3's stored hash no
                                      longer matches. Delete e2 -> the
                                      chain has a gap. Both detectable.
```

## The chain

```
  ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
  │   e1     │     │   e2     │     │   e3     │     │   e4     │
  │ dispatch │────▶│ tool_call│────▶│ approval │────▶│ execute  │
  │          │     │          │     │          │     │          │
  │ prev: "" │     │ prev: h1 │     │ prev: h2 │     │ prev: h3 │
  │ hash: h1 │     │ hash: h2 │     │ hash: h3 │     │ hash: h4 │
  └──────────┘     └──────────┘     └──────────┘     └──────────┘
                                                            │
                                                            ▼
                                                     chain head: h4
                                                     pinned into the
                                                     Attestation
```

Because the head hash is stored in the attestation, and the attestation is signed, tampering
with any event invalidates the signature over the whole run.

## Integrity is not completeness

A hash chain proves events were **not modified**. It does not prove they are **all** the
events that occurred.

```
   actual execution            what was recorded
   ────────────────            ─────────────────────────
   e1 → e2 → e3 → e4           e1 → e3 → e4

                               chain is internally VALID:
                               e3.prev == e1.hash
                               every hash recomputes
                               signature verifies
```

A defective or malicious host can simply omit an event. Nothing above detects it. For a
regulated system this is a material distinction, and it was missing from an earlier draft.

### Sealed runs

The fix is to bind a **count and range**, not just a linkage:

```
   ┌──────────────────────────────────────────────────┐
   │  RunSeal                                         │
   │    run_id                                        │
   │    event_count        11                         │
   │    sequence_range     1..11    (no gaps allowed) │
   │    head_hash          7f2a91c4                   │
   │    attestation_hash                              │
   │    signature                                     │
   └──────────────────────────────────────────────────┘
```

Each event carries a monotonic sequence number within its run. Verification checks that the
sequence is dense from 1 to `event_count` — so omitting `e2` now leaves a detectable gap, and
renumbering breaks the hash linkage.

### The sealer must be independent

```
   WEAK                                STRONGER
   ─────────────────────────           ────────────────────────────────
   application counts its own          an independent sealer assigns the
   events and seals the run            dense sequence and produces the
                                       seal; the application cannot
   An application that omits           instruct it to skip
   e2 also reports count=3.
   Self-certification.                 Options: a DB function + trigger,
                                       a separate sealing service, or
                                       an append-only log with its own
                                       ordering guarantee.
```

### Sequence numbers are assigned at SEAL time, not at insert time

This is the part an earlier draft got wrong, and it mattered.

The obvious reading — "the sink assigns a sequence number on every insert" — is incompatible
with the write model in [`../kernel/performance.md`](../kernel/performance.md), where effect
events are written immediately and everything else batches at run end. Under insert-time
assignment, an effect event written mid-run receives a *lower* sequence number than the
dispatch and evidence events that causally preceded it but are flushed later. The chain would
then attest that the payment was submitted before the evidence was retrieved.

The fix is to separate **durability order** from **canonical order**:

```
   application records CAUSAL STRUCTURE only
     (parent_event_id, branch_id, local_seq)
     - these are DAG edges, not a count; recording them
       certifies nothing
          │
          ▼
   durability          effect events  -> own transaction, immediately
                       everything else -> batched
          │
          ▼
   SEALER (below the application)
     1. reads the run's complete durable event set
     2. computes the canonical topological order
     3. assigns dense sequence 1..N
     4. builds the hash chain over that order
     5. signs
```

The application never chooses `N` — the sealer counts what is durably present. So the
independence property survives, batching survives, and causal order survives because ordering
is derived from the DAG rather than from write time. The canonical topological sort described
below stops being a competing scheme and becomes *the* ordering. See ADR 0034, superseding
0018.

A consequence worth stating: **there is no chain head until the run is sealed.** That is
correct — the chain is a post-hoc verification artifact, not a live index.

The residual risk, stated rather than designed away: an application that never flushes a
buffered event omits it, and the sealer cannot detect what it never saw. This is unchanged by
sealing, and it is exactly what receipts and external witnessing exist to cover — see
[`witness.md`](witness.md).

The Django adapter's default implements the sealer as a database function invoked at seal
time, with the append-only trigger below it. Hosts using another store must provide an
equivalent — it is a documented `AuditSink` contract obligation, tested by conformance.

### Sealing is still not enough on its own

A host that fully controls its own database can rewrite the entire chain at leisure —
recompute every hash, renumber every sequence, re-seal, re-sign. The result is internally
perfect and completely false, and nothing *inside* the system can detect it.

That requires evidence held where the host cannot reach it:

```
   seal        ──▶  defeats application-level omission and modification
   witness     ──▶  defeats wholesale history rewriting
                    (Merkle checkpoints + consistency proofs, published
                     to a third party)
   receipt     ──▶  defeats pre-publication omission
                    (the affected party holds a signed promise)
```

See [`witness.md`](witness.md), which closes this rather than accepting it. Witness level is
domain-selected — `NONE` for internal ops, `LOGGED` with receipts for legally binding
effects.

## Append-only, enforced below the application

Application-level "we only ever INSERT" is a convention, and conventions decay. Enforcement
belongs in the database:

```sql
-- shipped by the django adapter as a migration
CREATE TRIGGER audit_event_append_only
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();
```

One surveyed codebase already does exactly this. It is the right pattern and the framework
adopts it as the default for the Django adapter. Hosts using another store must satisfy the
same property — the `AuditSink` port documents it as a contract obligation.

## Execution is a graph; the audit stream is its canonical ordering

An earlier draft said "everything is still one chain," which understated what happens with
parallel branches. Execution is genuinely a DAG:

```
                  ┌─▶ branch A ─┐
   root ─▶ plan ──┼─▶ branch B ─┼─▶ gather ─▶ decision
                  └─▶ branch C ─┘
```

Flattening that directly into a sequence loses structure and makes concurrent ordering
arbitrary. The correct model is two layers:

```
   execution DAG          the true structure; each event records its
        │                 parent(s), so causality survives
        ▼
   canonical ordering     a deterministic topological sort
        │                 (by parent, then branch id, then local seq)
        ▼
   dense sequence 1..N    assigned by the sealer over that order
        │
        ▼
   hash chain             computed over the canonical order
```

This is the same ordering described under *Sequence numbers are assigned at seal time* above
— there is one ordering in the system, not one for concurrency and another for sealing.

An auditor still gets one ordered record with one head hash. A reviewer investigating
concurrency can recover the true topology. And because the ordering is deterministic, two
verifiers independently reach the same chain — which a naive "append in arrival order" scheme
does not guarantee under concurrency.

## Event taxonomy

Events are typed, not free-text. Free-text audit logs cannot be queried, aggregated, or
tested.

```
   RUN            dispatched · completed · failed
   EVIDENCE       retrieved · verified · rejected · stale
   TOOL           proposed · verified · executed · refused
   AUTHORITY      obligation_discharged · obligation_pending · obligation_failed
                  approval_requested · approved · rejected · expired
   BOUNDARY       injection_detected · pii_redacted · pii_restored
                  tenancy_violation
   MODEL          call_started · call_completed · retried · failed_over
                  budget_consumed · circuit_opened
   DOMAIN         (profiles register their own)
```

## What must never enter the chain

```
   ┌───────────────────────────────────────────────────────────────┐
   │  NEVER                        INSTEAD                          │
   ├───────────────────────────────────────────────────────────────┤
   │  raw PII / PHI                a redaction token + a pointer    │
   │  full prompt bodies           the prompt content hash          │
   │  full model outputs           a hash + the attestation ref     │
   │  credentials, keys            never, in any form               │
   └───────────────────────────────────────────────────────────────┘
```

The chain is append-only and often long-lived. Anything written there cannot be deleted — so
a right-to-erasure request against an audit chain containing raw PII is unanswerable. Store
the pointer; keep the erasable data where it can be erased.

## Verification

```python
result = verify_chain(events)      # walks the chain, recomputes every hash
```

Run it three ways:

```
   on demand      when a specific run is challenged
   scheduled      a periodic task over recent windows  (catches quiet tampering)
   on export      always, before an EvidenceBundle is produced
```

The scheduled sweep is the one that matters. Tampering discovered only when challenged is
tampering discovered too late.

## Signing

Chain integrity proves *internal* consistency. A signature proves the record came from this
system and not from someone reconstructing a plausible chain.

Settled by ADR 0012: signing is a pluggable `Signer` port — KMS by default, HSM optional, and
unsigned permitted only at the `THIN` assurance tier. Key custody is a deployment choice, not
the framework's. Chain verification works without signing; only the offline-evidence property
depends on it.

## Related

- [`../concepts/attestation.md`](../concepts/attestation.md) — where the head hash lands
- [`../kernel/ports.md`](../kernel/ports.md) — the `AuditSink` contract
- [`../assurance/export.md`](../assurance/export.md) — bundles include the chain
