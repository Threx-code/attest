# Chains

**Sequential composition, where each step's warrants carry forward.**

> **A pattern, not a mechanism.** A chain is a `Flow` with a linear topology. The primitive,
> the node kinds, and the warrant-composition rules all live in
> [`composition.md`](composition.md) — read that first. This document covers what is specific
> to sequential shapes: suspension, resumption, and compensation ordering.

A chain is not a pipeline of strings. It is a pipeline of attestations, and the composition
rules for warrants are the entire design problem.

## The shape

```
   ┌─────────┐      ┌─────────┐      ┌─────────┐      ┌─────────┐
   │ extract │─────▶│ assess  │─────▶│ price   │─────▶│ decide  │
   └────┬────┘      └────┬────┘      └────┬────┘      └────┬────┘
        │                │                │                │
        A1               A2               A3               A4
        │                │                │                │
        └────────────────┴────────────────┴────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │ ChainAttestation │
                    │  composes A1..A4 │
                    └──────────────────┘
```

## Warrant composition — the hard part

When step 3 cites step 2's output, what supports it?

```
   NAIVE (breaks the audit trail)        CORRECT (this design)
   ──────────────────────────────        ─────────────────────────────────
   step 3 cites "the assessment"         step 3 cites A2 as Derivation
   as a free-text fact                   evidence, whose sub-evidence is
                                         A2's own evidence tree
   The chain to source records
   is severed at every hop.              The tree stays connected all the
   An auditor cannot get from            way down to source records,
   the decision to the data.             across every hop.
```

Chained evidence is `Derivation` evidence (see
[`../capabilities/evidence.md`](../capabilities/evidence.md)). This is why `Derivation`
exists as a first-class kind rather than a convenience.

### Composition rules

```
   epistemic     union of steps; inter-step citations become Derivations
   authority     union of obligations; ALL must be discharged
   provenance    one continuous chain across every step
   boundary      strictest; a violation anywhere fails the chain
   domain kinds  the profile's WarrantPolicy decides
```

The **authority** rule deserves emphasis: obligations accumulate. A chain whose third step
needs approval holds the *whole chain*, not just that step. Executing steps 1–2, holding at
3, and leaving the system in a half-applied state is the failure mode this prevents.

## Verdict propagation

```
                  step verdict
                       │
      ┌────────────────┼────────────────┬──────────────┐
      ▼                ▼                ▼              ▼
    ALLOW          WARNINGS           HOLD          REFUSE
      │                │                │              │
   continue      continue, warnings   suspend       abort
                 accumulate           whole chain    chain
                       │                │              │
                       ▼                ▼              ▼
              chain ends WARNINGS   chain = HOLD   chain = REFUSE
                                    resumable      not resumable
```

A held chain is **suspended, not failed**. Its state is durable, and approval resumes it from
the held step — with every prior step's obligations re-discharged, because time has passed.

## Suspension and resumption

```
   ┌──────────────────────────────────────────────────────────┐
   │  chain suspended at step 3                               │
   │                                                          │
   │   steps 1-2   attestations persisted, effects applied    │
   │   step 3      PendingAction open, expires_at set         │
   │   steps 4-5   not started                                │
   │                                                          │
   │  on approval:                                            │
   │    re-discharge obligations for steps 1-3                │
   │    re-verify evidence from steps 1-2  (may be stale now) │
   │    resume at step 3                                      │
   └──────────────────────────────────────────────────────────┘
```

Re-verifying earlier evidence on resume is what catches the case where an approval sits in a
queue for three days and the underlying record changes underneath it.

## Compensation

Steps with irreversible effects need a compensating action when a later step fails.

```python
ChainSpec(
    steps=[
        Step("reserve_funds",  compensate="release_funds"),
        Step("notify_insurer", compensate=None),          # reversible; nothing to undo
        Step("issue_payment",  compensate=None),          # irreversible; must be LAST
    ]
)
```

The framework validates one rule at construction: **an irreversible step may not be followed
by a step that can fail without compensation.** A chain that can strand itself in a
half-applied state is rejected before it runs, not discovered in production.

This is a static check on the spec, so it costs nothing at runtime.

## When not to use a chain

Chains are sequential and each hop costs a model call. If steps are independent, use
fan-out — see [`orchestration.md`](orchestration.md). If a step is deterministic, it should
be a tool or plain host code, not an agent. Modelling a lookup as a chain step is the most
common way these systems become slow and expensive for no assurance benefit.

## Related

- [`orchestration.md`](orchestration.md) — non-sequential composition
- [`../capabilities/evidence.md`](../capabilities/evidence.md) — `Derivation`
- [`../capabilities/authority.md`](../capabilities/authority.md) — re-discharge on resume
