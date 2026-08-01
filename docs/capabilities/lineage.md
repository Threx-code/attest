# Data lineage — the lineage warrant

**Which records produced this model, and were they lawfully there?**

Every other capability governs a *decision*. This one governs the *artifact a decision-making
model was built from* — and it is the only capability whose central limit cannot be
engineered away.

> **Read [`../concepts/assurance-boundaries.md`](../concepts/assurance-boundaries.md) first.**
> The temptation here is to imply that provable lineage means controllable training data. It
> does not. See *The unlearning limit* below, which is the most important section in this
> document.

## The questions this answers

After a model makes a contested decision, the questions are not about the decision:

```
   1. Which exact records produced these weights?
   2. Was every one of them lawfully held, for this purpose?
   3. Did any contain data a subject has since required to be erased?
   4. Who authorised this training run, against what policy?
   5. Can the dataset be reconstructed, exactly, in six years?
```

A `SELECT` against a warehouse answers none of them, because the warehouse has moved on.

## A training run is an action

An earlier draft of this design assumed training sat outside the kernel's `Action` model. It
does not, and assuming so would have produced a parallel lifecycle for no reason.

```
   propose ──▶ verify args ──▶ discharge obligations ──▶ ISSUE GRANT ──▶ train ──▶ seal
                                                              │
        action_hash covers: dataset_root · base_model ────────┘
                            hyperparameters · code_version
```

The grant binds to the **dataset root**, so a run authorised against dataset `v7` cannot
silently train on `v8`. That is the same argument-binding property as
[`execution.md`](execution.md), applied to the input that actually matters.

The effect lifecycle applies unchanged, and `UNKNOWN` is as real here as for a payment:

```
   SUBMITTED persisted ──▶ training cluster ──▶ (job vanishes)
                                                      │
                                                      ▼
                                          UNKNOWN: did it produce weights?
                                          reconcile against the cluster,
                                          never assume either way
```

```python
EffectSemantics(
    reversible=False,          # weights can be deleted; what they encode cannot
    compensatable=False,       # retraining without a record is a NEW model,
                               # not a correction of this one
    financially_material=True, # compute spend is real
    idempotent_upstream=False, # never auto-retry a half-finished training run
)
```

## What is genuinely different: scale

The mismatch is not the lifecycle. It is that evidence trees are bounded — `max_depth` 8,
`max_nodes`, and an attestation budgeted at p50 under 8 KB
([`../kernel/storage.md`](../kernel/storage.md)) — and a training set has 10⁶–10⁹ leaves.

The resolution is the one `storage.md` already uses for wide derivations, taken to its limit:
**commit to the dataset, do not embed it.**

```
   records                                    leaf = H(canonical(record))
     r1   r2   r3   r4   ...   r(10⁹)
      │    │    │    │           │
      └─┬──┘    └─┬──┘           │
        └────┬────┘        ...   │            Merkle tree over the SORTED
             └──────────┬────────┘            leaf set
                        ▼
                  DATASET ROOT
                  root · leaf_count · epoch · manifest_hash
```

```
   dataset size    tree depth    inclusion proof    fits in an attestation
   ─────────────   ──────────    ───────────────    ──────────────────────
   1 million          20          20 hashes ~640 B         yes
   1 billion          30          30 hashes ~960 B         yes
```

A billion-record dataset is a **kilobyte** in the attestation. This is the same Merkle
machinery as [`witness.md`](witness.md), pointed at a different problem, and it is why this
capability is affordable at all.

## Two proofs, and the second is the useful one

```
 ┌────────────────────┬──────────────────────────────────────────────────┐
 │ INCLUSION          │ record R was in dataset D. O(log n).             │
 │                    │ "Yes, this customer's data trained the model."   │
 ├────────────────────┼──────────────────────────────────────────────────┤
 │ NON-INCLUSION      │ record R was NOT in dataset D. Requires the leaf │
 │                    │ set to be SORTED, then proves the two adjacent   │
 │                    │ leaves that bracket R's position.                │
 │                    │ "No, this record was excluded as required."      │
 └────────────────────┴──────────────────────────────────────────────────┘
```

Sorting the leaf set is what makes non-inclusion provable, and non-inclusion is what a data
protection officer actually needs. Answering "we excluded it, trust us" is not an answer.

## Lineage is a Derivation

Provenance is *where a record came from*. Lineage is *what happened to it on the way in* —
and that is structurally a derivation over sub-evidence, which already exists:

```
   Dataset "kyc_training@v7"                       Derivation
     ├── level summary: 4.2M records, leaf-set root 7f2a91c4
     ├── sampled leaves: 200 retained at DIGEST        <- verifiable
     ├── source: "core_banking.customers@2026-Q2"  RecordValue (referenced)
     ├── transform: "dedupe+redact v1.4"           Computation
     │     └── verify: re-run over the pinned input root; must reproduce v7
     └── excluded: 18,402 records, exclusion_root  Derivation
           └── reasons: no_lawful_basis · erasure_requested · out_of_jurisdiction
```

The **transform is a `Computation`**, so "does this pipeline actually produce this dataset
from that source?" is re-runnable rather than asserted. The exclusion set gets its own root
so that *what was deliberately left out* is as provable as what was included.

## Per-record provenance

Every leaf commits to more than the content:

```python
@dataclass(frozen=True, slots=True)
class LineageRecord:
    record_id: str
    content_hash: Hash
    source: SourceRef              # issuer, authority, version — see evidence.md
    lawful_basis: LawfulBasis      # domain-supplied taxonomy, never framework-defined
    consent_ref: ConsentRef | None
    jurisdiction: str
    collected_at: datetime
    subject_ref: SubjectRef | None # so erasure can find it later
```

`lawful_basis` is a **domain taxonomy**. The framework does not know what GDPR Article 6(1)(f)
or NDPA 2023 §25 means, and shipping that knowledge would breach
[`../00-thesis.md`](../00-thesis.md). It knows only that the profile's `DataPolicy` must
accept the basis before the record may be committed.

```python
def data_policy(self, purpose, ctx) -> DataPolicy:
    if purpose == TrainingPurpose.PRODUCTION_MODEL:
        return DataPolicy(
            accepted_bases={LawfulBasis.CONSENT, LawfulBasis.LEGAL_OBLIGATION},
            require_jurisdiction={"NG"},
            forbid_special_category=True,
        )
```

A record whose basis is not accepted **cannot enter the committed set** — it lands in the
exclusion tree with a reason. Filtering after commitment would prove nothing.

## The unlearning limit

**This is the section that must never be softened.**

```
   ┌──────────────────────────────────────────────────────────────────┐
   │  A model trained on data you must erase cannot un-learn it.      │
   │                                                                  │
   │  Deleting the record does not remove its influence on the        │
   │  weights. Machine unlearning is an open research problem, not    │
   │  an engineering task, and this capability does not solve it.     │
   └──────────────────────────────────────────────────────────────────┘
```

What the capability can do is convert an unanswerable question into a **tracked liability**:

```
   erasure request for subject S
        │
        ▼
   inclusion proofs against every dataset root
        │
        ▼
   ┌──────────────────────────────────────────────────────────┐
   │  ErasureImpact                                           │
   │    subject          S                                    │
   │    erased_at        2026-07-31                           │
   │    datasets         kyc_training@v5, @v6, @v7            │
   │    models_affected  fraud_score@2.1, fraud_score@2.2     │
   │    in_service       fraud_score@2.2      <- the finding  │
   │    remediation      REQUIRED | SCHEDULED | ACCEPTED_RISK │
   └──────────────────────────────────────────────────────────┘
   │
   ▼
   future datasets EXCLUDE S mechanically (the exclusion tree)
```

The record is erased from the store. The model that learned from it is *named*, its status is
*known*, and the decision to retrain or accept the risk is *recorded and owned by a human*.

That is a real contribution and it is not erasure. Any product surface that presents it as
erasure is misrepresenting the system.

## The forward link

A model artifact is used by thousands of later inference runs. Each must be able to reach its
training provenance, or the whole capability is an island.

```
   ModelRef
     provider · model_id · params · seed
     training_attestation: RunId | None      <- the link

   inference attestation ──▶ ModelRef ──▶ training attestation ──▶ dataset root
                                                                        │
                                                                        ▼
                                                              inclusion proofs
```

One nullable field on `ModelRef` in the `ExecutionContext`
([`../kernel/execution-context.md`](../kernel/execution-context.md)). `None` means a
third-party model whose training data we cannot attest to — which is the honest value for
every commercial API model, and must never be conflated with "trained on nothing".

## The warrant

```python
DATA_LINEAGE = WarrantKind("data_lineage")

@dataclass(frozen=True, slots=True)
class LineageReport(WarrantReport):
    kind = DATA_LINEAGE
    dataset: DatasetRef                    # root, leaf_count, epoch
    transform_reproduced: bool | None      # None when the pipeline is not re-runnable
    basis_coverage: BasisCoverage          # per basis: counts; unknowns are NOT zero
    excluded: ExclusionSummary             # root + reason histogram
    erasure_conflicts: Sequence[ErasureImpact]
    jurisdictions: frozenset[str]
```

`basis_coverage` counts records **whose lawful basis could not be established** separately
from those with none. Collapsing "unknown" into "absent" understates the problem; collapsing
it into "present" is a lie.

## What this does NOT establish

```
   ✓ which records were in the dataset          inclusion proofs
   ✓ which records were excluded, and why       exclusion tree
   ✓ that the pipeline reproduces the dataset   Computation re-run
   ✓ that each record had a declared basis      per-leaf commitment
   ─────────────────────────────────────────────────────────────────
   ✗ that the declared basis was CORRECT        a legal judgement
   ✗ that the model is fair                     see eval.md
   ✗ that erased data stopped influencing       impossible; see above
   ✗ that the training code did what it said    reproducibility only
                                                extends to determinism
                                                the host actually has
```

Row four deserves emphasis. Re-running a transform proves the *data pipeline* reproduces.
Bit-reproducible model training requires pinned hardware, kernels, and seeds that most
organisations do not control, so `transform_reproduced` covers the dataset, never the weights.

## Where it sits

```
   L1 capability. Reuses the Merkle machinery from witness.md.
   Ports:  DatasetStore   host holds the records; the framework holds
                          only the commitment. The framework must never
                          store 10⁹ records, and does not.
   Off the hot path: root construction is a batch job, like witnessing.
```

## Related

- [`witness.md`](witness.md) — the Merkle primitives this reuses
- [`evidence.md`](evidence.md) — `SourceRef`, `Derivation`, `Computation`
- [`../kernel/storage.md`](../kernel/storage.md) — summarising wide trees, erasure
- [`../concepts/assurance-boundaries.md`](../concepts/assurance-boundaries.md) — what is not provable
