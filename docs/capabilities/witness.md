# External witness

**Closes ADR 0026.** Sealing (see [`audit.md`](audit.md)) stops application-level event
omission. It does not stop a host that fully controls its own database from manufacturing a
consistent history after the fact.

```
   THE REMAINING THREAT
   ─────────────────────────────────────────────────────────
   A host can, at leisure, rewrite the entire chain:
     recompute every hash, renumber every sequence,
     re-seal, re-sign.

   The result is internally perfect and completely false.

   Nothing INSIDE the system can detect this, because the
   system is the thing that has been compromised.
```

Self-certification cannot answer this. The evidence must be held somewhere the host cannot
reach.

## The mechanism: checkpoints, proofs, receipts

You do not witness every event. You witness periodic **checkpoints**, and derive per-run
proofs from them. This is Certificate Transparency's model, and it is proven at scale.

```
   runs in a window
     r1  r2  r3  r4  r5  r6  r7  r8
      │   │   │   │   │   │   │   │      leaf = hash(attestation ‖ seal)
      └─┬─┘   └─┬─┘   └─┬─┘   └─┬─┘
        └───┬───┘       └───┬───┘        Merkle tree
            └───────┬───────┘
                    ▼
              CHECKPOINT
              root · tree_size · timestamp · signature
                    │
                    ▼
            published EXTERNALLY
            (log · TSA · anchor)
```

Two proofs fall out of the structure:

```
 ┌────────────────────┬──────────────────────────────────────────────────┐
 │ INCLUSION PROOF    │ this attestation is in checkpoint N.             │
 │                    │ O(log n) hashes. Proves the record existed at    │
 │                    │ that time and has not changed since.             │
 ├────────────────────┼──────────────────────────────────────────────────┤
 │ CONSISTENCY PROOF  │ checkpoint N+1 EXTENDS checkpoint N — nothing    │
 │                    │ was removed, reordered, or rewritten.            │
 │                    │ This is the one that defeats history rewriting.  │
 └────────────────────┴──────────────────────────────────────────────────┘
```

A host that rewrites history must publish a checkpoint inconsistent with one a third party
already holds. The forgery becomes **detectable by anyone**, not just by the host.

## Receipts close the omission gap

Checkpoints stop *rewriting*. They do not by themselves stop a run being **omitted before it
is ever included** — the host simply never adds the leaf.

```
   at decision time, synchronously:

   ┌──────────────────────────────────────────────────────┐
   │  RECEIPT                                             │
   │    run_id                                            │
   │    leaf_hash        = hash(attestation ‖ seal)       │
   │    promised_by      checkpoint window                │
   │    signature        (host key)                       │
   └──────────────────────────────────────────────────────┘
                          │
                          ▼
        issued to the counterparty / subject / regulator
        BEFORE or WITH the effect
```

Later, the holder demands an inclusion proof for that leaf. If the host cannot produce one,
**the signed receipt is unanswerable evidence of omission** — the host signed a promise it
did not keep.

This inverts the burden. The host no longer certifies its own completeness; the parties who
were affected hold the evidence.

## Witness levels

Cost and operational weight vary enormously, so this is tiered and domain-selected.

```
 ┌──────────────┬─────────────────────────────────┬─────────────────────┐
 │ LEVEL        │ MECHANISM                       │ DEFEATS             │
 ├──────────────┼─────────────────────────────────┼─────────────────────┤
 │ NONE         │ seal only                       │ app-level omission  │
 │              │ internal ops, triage            │ and modification    │
 ├──────────────┼─────────────────────────────────┼─────────────────────┤
 │ TIMESTAMPED  │ RFC 3161 TSA signs each         │ + backdating        │
 │              │ checkpoint root                 │ a whole window      │
 ├──────────────┼─────────────────────────────────┼─────────────────────┤
 │ LOGGED       │ append-only transparency log,   │ + history rewriting │
 │              │ third-party operated;           │   (consistency      │
 │              │ inclusion + consistency proofs  │    proofs)          │
 ├──────────────┼─────────────────────────────────┼─────────────────────┤
 │ ANCHORED     │ checkpoint roots published to a │ + collusion with    │
 │              │ widely-witnessed public medium  │   the log operator  │
 ├──────────────┼─────────────────────────────────┼─────────────────────┤
 │ + RECEIPTS   │ orthogonal; combine with any    │ + pre-publication   │
 │              │ level above                     │   omission          │
 └──────────────┴─────────────────────────────────┴─────────────────────┘
```

```python
def witness_policy(self, decision_type, ctx) -> WitnessPolicy:
    if ctx.legally_binding:
        return WitnessPolicy(level=LOGGED, receipt=True)
    if ctx.financially_material:
        return WitnessPolicy(level=TIMESTAMPED, receipt=True)
    return WitnessPolicy(level=NONE)
```

## Where it sits

Witnessing is **asynchronous and off the hot path** — it must not add latency to a decision.

```
   run completes ──▶ leaf queued
                          │
                          ▼
                   checkpoint window (e.g. 60s)
                          │
                          ▼
                   Merkle root ──▶ Witness port ──▶ external
                          │
                          ▼
                   inclusion proofs stored, retrievable per run
```

The **receipt** is synchronous — it is issued at decision time and contains only the leaf
hash, so it costs a hash, not a round trip.

```python
class Witness(Protocol):
    def submit(self, checkpoint: Checkpoint) -> WitnessReceipt: ...
    def inclusion_proof(self, leaf: Hash) -> InclusionProof | None: ...
    def consistency_proof(self, old: Checkpoint, new: Checkpoint) -> ConsistencyProof: ...
```

Shipped implementations: RFC 3161 TSA client, a generic Merkle transparency-log client, and
an in-memory witness for tests. Anchoring targets are host-supplied — the framework takes no
position on which public medium.

## Verification, from outside

An `EvidenceBundle` for a witnessed run additionally carries:

```
   bundle/
     ├── witness/
     │     ├── checkpoint.json      root, tree_size, timestamp, signature
     │     ├── inclusion_proof.json audit path for this leaf
     │     └── receipt.json         the promise issued at decision time
     └── VERIFY.md                  gains steps 6-8:
                                      6. recompute the leaf hash
                                      7. walk the inclusion proof to the root
                                      8. compare the root to the INDEPENDENTLY
                                         published checkpoint
```

Step 8 is the point: the verifier compares against a value obtained from the third party, not
from the bundle. That is what makes the whole chain externally trustworthy rather than
internally consistent.

The full bundle layout and the preceding steps 1–5 are in
[`../assurance/export.md`](../assurance/export.md); the numbering here continues that list
rather than restarting it.

## What remains, honestly

```
   ✓ history rewriting        detected by consistency proofs
   ✓ event omission           detected by seal + receipts
   ✓ backdating               detected by timestamping
   ✓ log operator collusion   mitigated by anchoring
   ────────────────────────────────────────────────────────────
   ✗ a run never executed     no witness proves a decision that was
     and never promised       never made was not made. Witnessing
                              covers what entered the system, not
                              what a compromised host declined to do.
```

The last line is a genuine limit and is not closeable by this or any similar mechanism. It is
the boundary between "the record is trustworthy" and "the operator is trustworthy," and only
the first is an engineering problem.

## Related

- [`audit.md`](audit.md) — sealing, the internal half
- [`../assurance/export.md`](../assurance/export.md) — bundles carry the proofs
- [`../assurance/threat-model.md`](../assurance/threat-model.md) — attacks 20 and 21
