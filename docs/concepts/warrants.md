# Warrants

A **warrant** is a defensible reason. Every agent action carries a set of them.

This is the framework's organising idea. Read this before anything else.

## The four core warrants

These four are mandatory for every action, in every domain, because they are universal to
any consequential automated decision.

```
 ┌────────────────┬──────────────────────────────────┬────────────────────────┐
 │ WARRANT        │ QUESTION IT ANSWERS              │ MACHINERY              │
 ├────────────────┼──────────────────────────────────┼────────────────────────┤
 │ EPISTEMIC      │ What evidence supports this?     │ evidence verification  │
 │ AUTHORITY      │ Was this permitted, for this     │ obligations, approvals │
 │                │ actor, at this moment?           │ capability gates       │
 │ PROVENANCE     │ What happened, in what order,    │ hash-chained audit     │
 │                │ and can the record be forged?    │ version pinning        │
 │ BOUNDARY       │ Did untrusted input steer it?    │ injection, PII,        │
 │                │ Did anything leak out?           │ tenancy, response guard│
 └────────────────┴──────────────────────────────────┴────────────────────────┘
```

> **Four is the floor, and it is not enough on its own.** The core four all validate what
> *was* used; none asks what was *missed*. See
> [`../capabilities/completeness.md`](../capabilities/completeness.md) for the coverage
> warrant, which is strongly recommended for any agent that retrieves or aggregates — and
> [`assurance-boundaries.md`](assurance-boundaries.md) for what a full set of satisfied
> warrants does and does not prove.

## The warrant set is OPEN

The four above are the floor, not the ceiling. A domain registers additional warrant kinds
that matter for its risk profile.

```
                          ┌─────────────────────┐
                          │   CORE (mandatory)  │
                          │   epistemic         │
                          │   authority         │
                          │   provenance        │
                          │   boundary          │
                          └──────────┬──────────┘
                                     │  every domain also gets...
       ┌──────────────┬──────────────┼──────────────┬──────────────┐
       ▼              ▼              ▼              ▼              ▼
  CALIBRATION    FAIRNESS     TEMPORAL_      CONTESTABILITY  RECONCILIATION
                              VALIDITY
  medical        mortgage     regulatory     insurance       reporting
  underwriting   banking      medical        mortgage        banking
       │              │              │              │              │
  "is the        "does this   "is the        "can the       "does this
   stated         decision     evidence       subject        tie back to
   confidence     differ by    still valid    contest it     source
   calibrated?"   protected    today?"        with a         records?"
                  class?"                     reason?"
```

None of these can live in the kernel. `FAIRNESS` requires knowing what a protected class is
— which differs by jurisdiction and domain. `TEMPORAL_VALIDITY` requires knowing how long a
clinical guideline or a regulation stays current. That knowledge belongs to the domain.

## The shape

```python
WarrantKind = NewType("WarrantKind", str)      # open, not an enum

EPISTEMIC  = WarrantKind("epistemic")
AUTHORITY  = WarrantKind("authority")
PROVENANCE = WarrantKind("provenance")
BOUNDARY   = WarrantKind("boundary")

CORE: frozenset[WarrantKind] = frozenset({EPISTEMIC, AUTHORITY, PROVENANCE, BOUNDARY})


class WarrantReport(Protocol):
    kind: WarrantKind
    satisfied: bool
    findings: Sequence[Finding]           # what was checked, and the outcome

    def verify(self, ctx: VerifyContext) -> VerificationResult: ...
```

`WarrantKind` is a `NewType` over `str`, **not an enum**. An enum is a closed set; adding
a domain would mean editing the kernel. That is precisely the failure this design exists to
avoid.

## How a domain adds one

```python
CALIBRATION = WarrantKind("calibration")

class CalibrationReport(WarrantReport):
    kind = CALIBRATION
    stated_confidence: float
    empirical_accuracy: float        # from the eval harness, per bucket
    brier_score: float

    @property
    def satisfied(self) -> bool:
        return abs(self.stated_confidence - self.empirical_accuracy) <= self.tolerance


class ClinicalProfile(DomainProfile):
    def warrant_kinds(self) -> frozenset[WarrantKind]:
        return CORE | {CALIBRATION, TEMPORAL_VALIDITY}
```

No kernel change. No enum edit. No framework release.

## Why not just "confidence scores" or "metadata"

Because a warrant is **verifiable after the fact**, and a metadata blob is not.

```
   metadata dict                    WarrantReport
   ─────────────────────            ───────────────────────────────
   {"confidence": 0.87}             .verify(ctx) -> VerificationResult
                                    re-runs the check against the
   Cannot be re-checked.            original evidence, months later,
   Cannot be falsified.             and can FAIL.
   Means whatever the writer
   thought it meant.                Typed. Machine-checkable.
```

The regulator's question is not "what did you think at the time?" It is "show me." A warrant
answers the second question.

## Failure semantics

A warrant that is not satisfied does not necessarily fail the run — that is the domain's
call, expressed as policy:

```
   warrant unsatisfied
          │
          ├── policy: BLOCK    -> verdict = REFUSE
          ├── policy: HOLD     -> verdict = HOLD_FOR_APPROVAL
          ├── policy: WARN     -> verdict = ALLOW_WITH_WARNINGS
          └── policy: RECORD   -> verdict = ALLOW  (finding still logged)
```

A medical profile might BLOCK on unsatisfied `EPISTEMIC`. A reporting profile might only
WARN, but BLOCK on unsatisfied `RECONCILIATION`. Same machinery, different policy.

## Related

- [`attestation.md`](attestation.md) — the artifact that carries warrants
- [`domain-profile.md`](domain-profile.md) — how a domain registers kinds
- [`../capabilities/evidence.md`](../capabilities/evidence.md) — the epistemic warrant
- [`../capabilities/authority.md`](../capabilities/authority.md) — the authority warrant
