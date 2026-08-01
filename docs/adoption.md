# Adoption

An earlier draft implied that ports make migration incremental. That is true for the gateway
and false for everything above it. This document sizes the gap honestly.

## What adoption actually costs

```
 ┌──────────────────────┬────────────┬──────────────────────────────────┐
 │ LAYER                │ EFFORT     │ WHY                              │
 ├──────────────────────┼────────────┼──────────────────────────────────┤
 │ Gateway only         │ days       │ implement 1 port, swap call      │
 │                      │            │ sites. Existing tables untouched.│
 ├──────────────────────┼────────────┼──────────────────────────────────┤
 │ + guards             │ days       │ config-driven; lift hardcoded    │
 │                      │            │ brand/currency into AttestConfig │
 ├──────────────────────┼────────────┼──────────────────────────────────┤
 │ + storage ports      │ 1-2 weeks  │ adapters over EXISTING tables    │
 │                      │            │ (no migration)                   │
 ├──────────────────────┼────────────┼──────────────────────────────────┤
 │ + domain profile     │ 2-4 weeks  │ the real work: evidence kinds,   │
 │                      │            │ obligations, warrant policy      │
 ├──────────────────────┼────────────┼──────────────────────────────────┤
 │ + agents & tools     │ weeks to   │ every agent definition, prompt,  │
 │   (the runtime)      │ months     │ and tool executor rewritten      │
 ├──────────────────────┼────────────┼──────────────────────────────────┤
 │ + execution boundary │ 1-2 weeks  │ grants, effect lifecycle,        │
 │                      │            │ reconciliation                   │
 └──────────────────────┴────────────┴──────────────────────────────────┘
```

**Be honest with adopting teams: full adoption of a mature AI layer is a quarter, not a
sprint.** A survey of six existing backends found ~101k LOC of AI-layer code; the gateway is
perhaps 5% of that.

## The value ladder

Each rung is independently valuable and independently reversible. Nothing requires the next.

```
   1. GATEWAY          failover, budget, cost attribution, drift
      │                value: immediate, no migration, no schema change
      ▼
   2. GUARDS           injection, PII, tenancy — config-driven
      │                value: closes the most common real defects
      ▼
   3. AUDIT + STORAGE  attestations over your existing tables
      │                value: the record becomes verifiable
      ▼
   4. PROFILE          evidence verification, obligations, warrants
      │                value: the epistemic and authority warrants
      ▼
   5. EXECUTION        grants, effect lifecycle, reconciliation
      │                value: TOCTOU and UNKNOWN handled
      ▼
   6. RUNTIME          declarative agents, flows, replay
                       value: the full framework
```

Most teams should stop and stabilise after 3. A team that adopts 1–3 and never goes further
has still removed the duplication that motivated the framework.

## Migration is not required to be complete

Two systems can coexist indefinitely:

```
   existing agents  ──┐
                      ├──▶ attest gateway ──▶ providers
   attest agents    ──┘

   Both get failover, budget, and drift.
   Only the second gets attestations.
```

This matters more than it sounds: it removes the all-or-nothing decision that stalls
framework adoption, and it means the first migrated agent proves value before the second is
started.

## Sequencing across a portfolio

```
   1. ONE agent, in ONE project, end to end
      Prove the ports fit. Measure the cost (performance.md).
      Expect the profile to be wrong; it is meant to be a draft.

   2. The REST of that project's agents
      Now the profile is real and the marginal cost per agent is small.

   3. A project on the OPPOSITE lineage
      A retrieval-heavy domain if the first was tool-heavy, or vice
      versa. This is what proves the abstraction rather than the
      implementation.

   4. Everything else, as capacity allows
```

Step 3 is the one teams skip and should not. Two projects of the same shape prove nothing
about openness.

## What blocks adoption, honestly

```
   ✗ no versioned source data      -> UNVERIFIABLE evidence (see storage.md)
   ✗ no capability model           -> obligations have nothing to check
   ✗ effects with no idempotency   -> execution boundary cannot be safe
   ✗ no reviewer capacity          -> HOLD verdicts become a backlog
   ✗ prompt bodies in code         -> content addressing needs a registry
```

These are host prerequisites, not framework work. A team without a capability model will
spend longer building one than adopting the framework, and should know that before starting.

## The first-profile problem

`BaseProfile` reduces the minimum viable profile to two overrides
([`concepts/domain-profile.md`](concepts/domain-profile.md)), and the scaffolding generator
produces a working skeleton plus a conformance suite:

```
   attest new-profile mortgage --jurisdiction UK
     -> profile package, six sub-profile stubs with defaults,
        conformance test class, golden-set skeleton, red-team extras stub
```

Target: **a first profile that passes conformance in under a day**, then weeks of refinement
as the domain is understood. If the first profile takes weeks before anything runs, the
open-world claim is practically false. This is the mitigation.

## Related

- [`kernel/performance.md`](kernel/performance.md) — measure before committing
- [`kernel/ports.md`](kernel/ports.md) — what "no migration" rests on
- [`concepts/conformance.md`](concepts/conformance.md) — proving the profile fits
