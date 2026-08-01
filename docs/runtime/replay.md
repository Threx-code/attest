# Replay

**Re-execute a historical run and diff it.** The capability that makes "why did the system
decide that?" answerable a year later.

## What replay needs

```
   ┌─────────────────────────────────────────────────────────────┐
   │  captured at run time, in the ProvenanceChain               │
   ├─────────────────────────────────────────────────────────────┤
   │   model id + provider + whether it was a failover           │
   │   sampling parameters + seed                                │
   │   prompt content hashes (every fragment)                    │
   │   domain profile name + version                             │
   │   pricing table version                                     │
   │   every retrieved evidence item, by id and content hash     │
   │   every tool call and its exact result                      │
   │   the clock value at dispatch                               │
   └─────────────────────────────────────────────────────────────┘
```

Anything not captured here makes replay approximate, and an approximate replay cannot
support a claim about a past decision.

## Three modes — named for the question each answers

Naming matters here more than usual. "We replayed the decision" is ambiguous in a way that
becomes dangerous in front of a regulator: it can mean "we reconstructed what happened" or
"we ran today's model against old inputs," and those are not equivalent claims.

```
   REPLAY_HISTORICAL     What exactly happened?
                         Recorded model outputs, recorded tool results.
                         No live calls. Reconstructs the run as it ran.

   REPLAY_VERIFY         Does the attestation still verify?
                         No model calls at all. Recomputes chain, seal,
                         evidence, warrants against the captured context.
                         This is verify_historical(), executed.

   REPLAY_BEHAVIOURAL    What would the system do now?
                         Live model calls, current profile and policy,
                         recorded tool results.
                         Answers a DIFFERENT question from the first two.
```

```
 ┌────────────────────┬──────────┬────────────┬─────────────────────────────┐
 │ MODE               │ MODEL    │ POLICY     │ VALID CLAIM                 │
 ├────────────────────┼──────────┼────────────┼─────────────────────────────┤
 │ REPLAY_HISTORICAL  │ recorded │ as at then │ "this is what happened"     │
 │ REPLAY_VERIFY      │ none     │ as at then │ "the record is sound"       │
 │ REPLAY_BEHAVIOURAL │ live     │ current    │ "this is what we'd do now"  │
 └────────────────────┴──────────┴────────────┴─────────────────────────────┘
```

**Never describe `REPLAY_BEHAVIOURAL` output as a replay of the original decision.** It is a
counterfactual against a system that has changed. The API keeps the names distinct so a
report cannot quietly blur them.

Drift measurement is `REPLAY_BEHAVIOURAL` with the profile and policy held at their
historical versions, so the model is the only variable — see
[`../capabilities/llm-gateway.md`](../capabilities/llm-gateway.md).

```
   original run                replay
   ────────────                ──────────────────────────────
   Attestation A    ──────▶    Attestation A'
                                     │
                                     ▼
                                A.diff(A')
                                     │
                    ┌────────────────┼────────────────┐
                    ▼                ▼                ▼
              same verdict     different verdict   evidence
              same evidence    -> investigate      no longer
              -> reproducible                      verifies
                                                   -> tampering or
                                                      data drift
```

## Determinism is a design constraint, not a feature

Replay works because the core is deterministic **over a captured `ExecutionContext`** — not
in general. Capability checks, budget checks, and referential verification all read external
state, which is snapshotted at dispatch. See
[`../kernel/execution-context.md`](../kernel/execution-context.md).

Three rules, enforced in the kernel:

```
   1. no datetime.now()      the Clock port is injected
   2. no random / uuid4      seeded, or supplied
   3. no ambient config      everything arrives through AttestConfig
```

The conformance kit tests these. A single `datetime.now()` in a prompt template silently
breaks replay for every agent that uses it, and nothing else will catch it.

## What replay cannot prove

Worth stating plainly:

- It cannot prove the decision was **right** — only that it was reproducible and warranted.
- `CURRENT` mode differences are expected and are not evidence of a past error. A model that
  decides differently today may simply be better.
- It cannot replay side effects. Tool results are replayed from the record; the effects
  themselves are not re-executed. Replay is read-only by construction, and the framework
  refuses to run a tool with non-`NATURAL` idempotency during replay.

## Uses

```
   incident review     REPLAY_HISTORICAL   what exactly happened in run X
   drift detection     REPLAY_BEHAVIOURAL  canary set, policy=AS_AT_RUN, so
                       (scheduled)         the model is the only variable
   policy assessment   REPLAY_BEHAVIOURAL  a historical sample, policy=CURRENT,
                                           before changing a threshold —
                                           how many decisions flip?
   regression testing  REPLAY_VERIFY       in CI over a golden set
```

**There is one set of mode names.** An earlier draft also used `STRICT`, `PINNED` and
`CURRENT` in this section and in [`../kernel/determinism.md`](../kernel/determinism.md) —
four names for three modes, with `STRICT` ambiguous between `HISTORICAL` and `VERIFY` since
both avoid live model calls. Those names are withdrawn. What varied between `PINNED` and
`CURRENT` is not a mode but a parameter:

```python
replay(run_id, mode=REPLAY_BEHAVIOURAL, policy=PolicyAt.AS_AT_RUN)  # drift
replay(run_id, mode=REPLAY_BEHAVIOURAL, policy=PolicyAt.CURRENT)    # policy assessment
```

The policy-assessment use is the one teams find most valuable and never build: before
changing an approval threshold, replay six months of decisions and count how many change.

## Related

- [`../kernel/determinism.md`](../kernel/determinism.md) — the rules
- [`../capabilities/llm-gateway.md`](../capabilities/llm-gateway.md) — drift detection
- [`../assurance/eval.md`](../assurance/eval.md) — replay in CI
