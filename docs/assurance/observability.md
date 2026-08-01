# Observability

Listing OpenTelemetry as an adapter is not an observability story. For a framework whose entire value is trust, production
visibility is core, and several signals require the runtime to emit data **by design** rather
than to be instrumented later.

## The four questions operators must be able to answer

```
   1. Is assurance degrading?        warrants failing more often than yesterday
   2. Is the governance real?        or is it discharging without meaning
   3. What will break next?          leading indicators, not post-mortems
   4. What did this decision cost?   per domain, per tenant, per actor
```

## Signals the runtime must emit

These are not optional instrumentation. Each is derived from data only the kernel holds.

```
 ┌──────────────────────┬────────────────────────────────────────────────┐
 │ ASSURANCE            │ warrant satisfaction rate, by kind and domain  │
 │                      │ verdict mix — all six, and the last two are    │
 │                      │ the ones that matter: unknown, incomplete      │
 │                      │ refusal rate BY REASON                         │
 │                      │ non-final (deferred) attestation rate          │
 │                      │ UNVERIFIABLE rate  <- source systems degrading │
 │                      │ retraction rate (streaming)                    │
 ├──────────────────────┼────────────────────────────────────────────────┤
 │ JUDGE HEALTH         │ judge disagreement rate on panels              │
 │                      │ judge-vs-human agreement (from control items)  │
 │                      │ calibration drift per judge                    │
 ├──────────────────────┼────────────────────────────────────────────────┤
 │ GOVERNANCE REALITY   │ approval time-to-decision distribution         │
 │                      │ per-reviewer approval rate                     │
 │                      │ CONTROL ITEM approval rate  <- the sharpest    │
 │                      │ evidence-expanded rate                         │
 │                      │ post-hoc reversal rate                         │
 ├──────────────────────┼────────────────────────────────────────────────┤
 │ EXECUTION SAFETY     │ UNKNOWN effect count and AGE                   │
 │                      │ reconciliation lag                             │
 │                      │ grant expiry / replay rejections               │
 │                      │ effect-vs-audit divergence                     │
 ├──────────────────────┼────────────────────────────────────────────────┤
 │ INTEGRITY            │ scheduled chain verification failures          │
 │                      │ seal gap detections                            │
 │                      │ export verification failures                   │
 ├──────────────────────┼────────────────────────────────────────────────┤
 │ COST & CAPACITY      │ cost per decision, by domain and tenant        │
 │                      │ tier budget breaches (see performance.md)      │
 │                      │ approval queue depth and age                   │
 │                      │ projected vs staffed review capacity           │
 ├──────────────────────┼────────────────────────────────────────────────┤
 │ PROVIDER             │ circuit breaker state, failover rate           │
 │                      │ drift canary results                           │
 └──────────────────────┴────────────────────────────────────────────────┘
```

## The signals that must page someone

Most of the above is a dashboard. These are incidents:

```
   ┌──────────────────────────────────────────────────────────────────┐
   │  PAGE                                                            │
   │    chain verification failure          integrity compromised     │
   │    seal gap detected                   events omitted            │
   │    UNKNOWN effect older than SLA       money in an unknown state │
   │    effect-vs-audit divergence          the two records disagree  │
   │    control item approved               oversight is not real     │
   │    cross-tenant access detected        data boundary breached    │
   └──────────────────────────────────────────────────────────────────┘
```

`UNKNOWN effect age` deserves emphasis: an unreconciled £500,000 transfer is not a metric on a
chart, it is an open incident, and its SLO belongs in the same tier as availability.

## Leading indicators

The valuable ones are the signals that move *before* the failure:

```
   UNVERIFIABLE rate rising
        └─▶ a source system stopped retaining versions
            -> future attestations lose their evidentiary value
               MONTHS before anyone tries to verify one

   judge disagreement rising
        └─▶ generator or judge behaviour has shifted
            -> check the drift canary

   approval time-to-decision falling
        └─▶ reviewers are speeding up
            -> capacity problem becoming a governance problem

   evidence-expanded rate falling
        └─▶ reviewers stopped opening the tree
            -> the summary is wrong, or attention is gone
```

None of these is visible in conventional APM. All of them predict a failure that is expensive
once it arrives.

## Tracing

One trace per run, spans matching the pipeline, with the run id correlating trace, attestation,
and audit chain.

```
   run  ─────────────────────────────────────────────────────
     ├─ guards.in
     ├─ context.capture
     ├─ model.call            (provider, model, tokens, failover?)
     ├─ tool.propose ─ verify ─ discharge ─ grant ─ execute
     ├─ evidence.verify       (per item, kind)
     ├─ warrants.evaluate     (per kind)
     ├─ guards.out
     └─ attestation.persist
```

**Trace attributes must never carry evidence content, PII, or prompt bodies** — hashes and
ids only. Tracing backends are rarely in the compliance boundary, and a trace is the easiest
accidental exfiltration path in the whole system.

## Tenant and domain dimensions

Every metric carries `tenant`, `domain`, `profile_version`, and `agent`. Without these, a
degradation confined to one tenant or one profile version is invisible in the aggregate —
and that is the normal shape of a real incident.

Cardinality is bounded by keeping actor out of metric labels; per-actor analysis runs over
the attestation store, not the metrics backend.

## Related

- [`../kernel/performance.md`](../kernel/performance.md) — budgets that these verify
- [`../capabilities/approvals.md`](../capabilities/approvals.md) — governance-reality signals
- [`../capabilities/execution.md`](../capabilities/execution.md) — UNKNOWN and reconciliation
