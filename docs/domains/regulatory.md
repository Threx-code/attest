# Regulatory

Compliance monitoring, filings, and change impact. The domain where **deadlines are
obligations** and the rules themselves keep moving.

## 1. What is a claim?

> "The amended reporting threshold in SI 2026/412 reg. 7 applies to this entity from
> 2026-10-01; three existing controls require revision."

## 2. What supports it?

```
   "threshold amended to £8m"        QuotedSpan
     ├── SI 2026/412, reg. 7(2), chars 3,102-3,158
     └── verify: substring present at offset in that instrument

   "entity turnover is £11.2m"       RecordValue
     └── filed accounts, FY2025

   "in scope from 2026-10-01"        Derivation
     └── over the commencement provision and the entity record

   "three controls require revision" Derivation
     └── over the control register, matched against the amended rule
```

Note this domain is unusual: the **evidence itself is the thing that changes**. Elsewhere
records change and rules are stable. Here the corpus of rules is the moving part, and change
detection is the primary workload.

## 3. What must be true before acting?

```python
def obligations_for(self, action, ctx):
    obs = [CapabilityCheck(action.capability)]

    if action.name == "submit_filing":
        obs += [
            ReviewAttestation("compliance_officer"),
            TimeWindow(before=ctx.statutory_deadline),   # <- the hard one
            Approval(n=1, roles={"company_secretary"}),
            Reversibility(action),        # a filing cannot be unfiled
        ]
    if action.name == "update_control":
        obs += [Notification("control_owner", before_effect=True)]
    return ObligationSet(obs)
```

`TimeWindow(before=deadline)` is an obligation that **fails with the passage of time** rather
than through any action. That is a shape a ladder cannot express at all: nothing about the
actor's autonomy level changes: the deadline simply passes.

It also interacts with holds. An approval sitting in a queue while the deadline approaches
must escalate, which is why `PendingAction.expires_at` is mandatory — see
[`../capabilities/authority.md`](../capabilities/authority.md).

## 4. What do the core four warrants miss?

```
   TEMPORAL_VALIDITY   Which version of the rule was in force on the
                       relevant date? Instruments are amended, commenced
                       in stages, and sometimes retrospective.
                       A citation to the consolidated current text is
                       verifiable and wrong for a past period.

   CONTESTABILITY      A compliance determination affecting a business
                       unit must be explainable to that unit, with the
                       specific provision and the specific fact that
                       triggered it.
```

Staged commencement is the detail that catches naive implementations: a single instrument
can have different provisions in force on different dates. `validity()` must answer per
provision, not per document.

## 5. What must a regulator be shown?

```
   the determination, the instrument text as at the relevant date,
   the entity facts relied on, the commencement analysis, the
   compliance officer's attestation, and the filing timestamp
```

## Warrant policy

```
   temporal_validity  BLOCK    <- the load-bearing warrant here
   epistemic          BLOCK
   contestability     HOLD
   boundary           BLOCK
```

`temporal_validity` is `BLOCK` in this domain and `WARN` in
[`reporting.md`](reporting.md) — the clearest illustration that warrant *policy* is domain
data while warrant *machinery* is framework code.

## Change impact as the primary workload

Most regulatory agent work is not answering questions. It is:

```
   a rule changes
        │
        ▼
   which entities are now in scope?          fan-out over entities
        │
        ▼
   which controls are affected?              fan-out over the register
        │
        ▼
   what must change, by when?                per-item attestation
```

This is a fan-out topology, not a chain — see
[`../runtime/orchestration.md`](../runtime/orchestration.md). Each affected item gets its own
attestation, so an entity can dispute its own determination without re-opening the others.

## Corpus epochs

When an instrument is amended, every cached answer derived from the old text must be
invalidated. The gateway's corpus epoch marker handles this — see
[`../capabilities/llm-gateway.md`](../capabilities/llm-gateway.md). Without it, a semantic
cache serves pre-amendment answers indefinitely, which in this domain is the worst possible
failure.
