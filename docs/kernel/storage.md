# Storage and retention

Attestations are immutable and accumulate.
Without a retention model, the cost of assurance exceeds the cost of the system being assured.

## The tension, stated

```
   C3  attestations must be SMALL         millions of runs/day
   S2  attestations must be SELF-         source systems are often
       VERIFYING (embed cited values)     last-write-wins, so a later
                                          re-query cannot verify anything
```

An earlier draft said: *cannot have both.* That was a false dilemma — it treated the choice
as global when it is properly **per decision**.

## Resolution: materiality decides

```
                         materiality of the decision
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
   ┌──────────┐              ┌────────────┐              ┌────────────┐
   │ REFERENCE│              │  DIGEST    │              │  EMBEDDED  │
   ├──────────┤              ├────────────┤              ├────────────┤
   │ source id│              │ id + hash  │              │ id + hash  │
   │ + hash   │              │ + the cited│              │ + FULL     │
   │          │              │   value/   │              │   retrieved│
   │          │              │   span     │              │   content  │
   ├──────────┤              ├────────────┤              ├────────────┤
   │ ~200 B   │              │ ~2 KB      │              │ ~50 KB-5 MB│
   │ per item │              │ per item   │              │ per item   │
   ├──────────┤              ├────────────┤              ├────────────┤
   │ verify:  │              │ verify:    │              │ verify:    │
   │ needs the│              │ SELF, for  │              │ SELF, fully│
   │ source   │              │ the cited  │              │ offline    │
   │ -> often │              │ value only │              │            │
   │ UNVERIF. │              │            │              │            │
   └──────────┘              └────────────┘              └────────────┘
   triage, support           most regulated              payments, filings,
   internal ops              decisions                   clinical, adverse
                                                         decisions
```

`DIGEST` is the default and the right answer for most regulated work: it embeds *the value
that was cited*, not the whole source. A £12,400 excess and the 64-character span it came
from are self-verifying at 2 KB. The 40-page policy document is referenced by hash.

The profile chooses per decision type:

```python
def evidence_persistence(self, decision_type, ctx) -> Persistence:
    if ctx.amount > Money("10000", "GBP"):     return Persistence.EMBEDDED
    if decision_type == "adverse_decision":    return Persistence.EMBEDDED
    if decision_type == "triage":              return Persistence.REFERENCE
    return Persistence.DIGEST
```

## Wide trees summarise

`domains/reporting.md` describes a 412-leaf derivation. Embedding all of it is untenable and
unnecessary.

```
   Derivation "Q3 provision £4.2m"
     ├── level summary:  412 leaves, sum £3.8m, hash of the leaf set
     ├── sampled leaves: 20 retained at DIGEST                <- verifiable
     └── full leaf set:  REFERENCE, expandable on demand
                         from the source system while it exists
```

The **leaf-set hash** is what preserves integrity: adding, removing, or altering any leaf
changes it, so the summary detects tampering even though the leaves are not embedded. Drilling
down is possible while the source lives; verification of the *total* does not depend on it.

## Lifecycle

```
   HOT        0-90 days      full attestation, queryable, indexed
    │
    ▼
   WARM       90d - N years  evidence compacted to DIGEST,
    │                        provenance chain retained in full
    ▼
   COLD       to limitation  attestation + chain + manifest hashes only;
    │         period end     bundles rebuilt on demand from archive
    ▼
   PURGE      after the      cryptographic erasure of subject data;
              statutory      the chain retains hashes, so integrity
              period         survives erasure
```

**Retention is domain-supplied**, because the statutory period is: six years for UK financial
records, twenty-five years for some clinical records, indefinite for certain regulatory
filings.

```python
def retention(self, decision_type, ctx) -> RetentionPolicy: ...
```

## Erasure without breaking the chain

Right-to-erasure and an immutable audit chain appear to conflict. They do not, if subject
data never enters the chain in the first place.

```
   chain holds       hashes, pointers, event types, timestamps
   store holds       the erasable payload, keyed by pointer

   erasure  ->  delete the payload
                the chain still verifies (hashes unchanged)
                the attestation reports UNVERIFIABLE for erased items
                             ^^^^^^^^^^^^
                             honest, and distinct from FAIL
```

This is why `audit.md` forbids raw PII in the chain, and why
[`../concepts/attestation.md`](../concepts/attestation.md) needs a third verification
outcome.

## Corrections never mutate

```
   attestation v1  ──superseded_by──▶  attestation v2
        │                                   │
        └── both retained; v1 is what        └── the correction, with
            downstream consumers acted on        its own full warrants
```

`supersede`, never `update`. A reader who relied on v1 must be able to see exactly what they
relied on.

## Budgets

```
   attestation size    p50 < 8 KB   p95 < 64 KB   (DIGEST tier)
   storage per run     measured in attest.bench, fails CI on regression
```

## Related

- [`performance.md`](performance.md) — the latency half of the cost
- [`../concepts/attestation.md`](../concepts/attestation.md) — `UNVERIFIABLE`
- [`../assurance/export.md`](../assurance/export.md) — rebuilding bundles from cold storage
