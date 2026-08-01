# Performance

The assurance machinery has a cost. If that cost is not bounded and
measured, the framework loses the low-stakes work — and then loses the high-stakes work,
because teams standardise on the stack they already run.

## The budget is a contract, not an aspiration

Every profile declares an **assurance tier**. The tier fixes what runs on the hot path.

```
 ┌────────┬──────────────────────────────┬───────────────┬──────────────────┐
 │ TIER   │ ON THE HOT PATH              │ ADDED LATENCY │ ADDED MODEL SPEND│
 ├────────┼──────────────────────────────┼───────────────┼──────────────────┤
 │ THIN   │ guards, provenance, budget   │   < 15 ms     │      0 %         │
 │        │ no evidence verification     │               │                  │
 │        │ no warrant evaluation        │               │                  │
 ├────────┼──────────────────────────────┼───────────────┼──────────────────┤
 │ STD    │ + exact evidence verification│   < 60 ms     │      0 %         │
 │        │ + warrant evaluation         │               │                  │
 │        │ + completeness (declarative) │               │                  │
 ├────────┼──────────────────────────────┼───────────────┼──────────────────┤
 │ FULL   │ + entailment on a sample     │   < 250 ms    │   +10-25 %       │
 │        │ + source authority checks    │   (p50)       │                  │
 ├────────┼──────────────────────────────┼───────────────┼──────────────────┤
 │ MAX    │ + entailment on every claim  │  +1 model call│   +100-300 %     │
 │        │ + adversarial critic         │   per claim   │                  │
 └────────┴──────────────────────────────┴───────────────┴──────────────────┘
```

`THIN` is the load-bearing tier. Internal ops, support, triage, and document classification
run here, and the overhead must be indistinguishable from a bare gateway call. If `THIN`
costs more than ~15 ms, the framework has failed the requirement in
[`../domains/catalog.md`](../domains/catalog.md).

## What moves off the hot path

The default in an earlier draft was to compute everything at run time. Most of it does not
need to be.

```
   AT RUN TIME (hot)                  DEFERRED (cold)
   ────────────────────────           ──────────────────────────────
   guards in/out                      entailment judging
   provenance append                  source authority resolution
   obligation discharge               warrant re-evaluation
   authorization grant                export bundle assembly
   exact evidence verification        derivation tree expansion
   completeness (declarative)         calibration scoring
```

```
   run completes ──▶ attestation ALLOW, is_final == False
        │             (warrants carry status PENDING)
        ▼
   async assurance queue
        │
        ├── entailment sample
        ├── source authority
        └── deep verification
                │
                ▼
        warrants finalised -> is_final == True
                │
        ┌───────┴────────┐
        ▼                ▼
     unchanged        DOWNGRADED
                      -> supersede the attestation
                      -> notify per profile policy
```

### Provisional is visible in the type, not just in the docs

A consumer holding an `ALLOW` must be able to tell whether its warrants were actually
evaluated. Otherwise deferred assurance is exactly the failure this framework exists to
prevent: an unverified result presented as a definitive one.

```python
class WarrantStatus(StrEnum):
    EVALUATED    = "evaluated"      # the check ran and produced a result
    PENDING      = "pending"        # deferred; not yet run
    UNEVALUATABLE = "unevaluatable" # could not be run; NEVER read as a pass
```

`Attestation.is_final` is **derived**, not stored: it is true only when every warrant is
`EVALUATED`. Two consequences are enforced rather than documented:

```
   a non-final attestation CANNOT be exported as an EvidenceBundle
   a non-final attestation CANNOT be serialised without its assurance state
```

An evidence bundle is what goes to a regulator. Shipping one whose warrants had not yet been
evaluated would misrepresent the record, so the export path refuses it. See ADR 0035 and
[`../assurance/export.md`](../assurance/export.md).

**Deferred assurance is only legitimate where the effect is reversible or delayed.** A
profile whose action is an irreversible payment must not defer — the framework refuses the
combination at construction:

```
   EffectSemantics.reversible == False
     AND profile.assurance == DEFERRED
     -> configuration error, fails at startup
```

## Write amplification

An earlier draft appended 5–15 audit events per run as individual writes. That is the
dominant cost at volume.

```
   BEFORE                        AFTER
   ──────────────────            ────────────────────────────
   15 individual INSERTs         1 batched INSERT at run end
   per run                       + 1 immediate INSERT for any
                                   effect event (never batched)

   AML at 2M runs/day            effect events are ~2% of the
   = 30M writes/day              total but 100% of the risk
```

Effect events (`SUBMITTED`, `COMMITTED`, `UNKNOWN`) are written **immediately and
individually** — they are the events whose loss creates an unreconcilable state. Everything
else batches.

**Batching does not disturb ordering**, because the dense sequence is not assigned at insert
time. The application records causal structure (`parent_event_id`, `branch_id`, `local_seq`);
the independent sealer computes the canonical topological order over the run's complete
durable event set and assigns `1..N` at seal time. So an effect event flushed mid-run and a
guard event flushed at run end are ordered by causality, not by which transaction committed
first.

Without that separation the two requirements are contradictory: insert-time sequence
assignment plus end-of-run batching would give the mid-run effect event a lower sequence
number than the evidence retrieval that preceded it. See
[`../capabilities/audit.md`](../capabilities/audit.md) and ADR 0034.

## Measuring, not asserting

Every number above is a **budget with a test**, not a claim:

```
   attest.bench
     ├── per-tier latency, p50 / p95 / p99
     ├── write count per run
     ├── attestation size, p50 / p95
     ├── model spend delta vs a bare gateway call
     └── FAILS CI if a tier exceeds its declared budget
```

A regression that pushes `THIN` past 15 ms breaks the build. This is the only way a
performance requirement survives eighteen months of feature work.

## Known costs that are not optimised away

Stated honestly:

- **Grant issuance** adds a hash and a store write before every effect. Non-negotiable; it is
  the TOCTOU defence.
- **Context capture** reads identity, policy, and budget once per run. Cacheable per actor
  for short windows, but never skipped.
- **Guards** run on every untrusted input, including every tool result. At high tool-call
  counts this is linear and unavoidable.

## Related

- [`../domains/catalog.md`](../domains/catalog.md) — why the thin path decides adoption
- [`../capabilities/execution.md`](../capabilities/execution.md) — why effect events cannot batch
- [`storage.md`](storage.md) — attestation size, the other half of the cost
