# Evaluation

**Golden sets and regression gates.** Conformance proves a domain is well-formed; evaluation
proves it is right.

```
   conformance  ──▶  "the machinery is intact"     (structural, in CI)
   evaluation   ──▶  "the answers are correct"     (empirical, in CI)
   redteam      ──▶  "it resists attack"           (adversarial, in CI)
```

## Golden sets

A golden set is cases with known-correct outcomes, owned by the domain.

```python
GoldenCase(
    id="claim-8823-water-damage",
    input={...},
    fixtures={...},                    # pinned evidence, pinned tool results
    expect=Expectation(
        verdict=HOLD_FOR_APPROVAL,
        obligations_pending={"approval:claims_manager"},
        warrants_satisfied={EPISTEMIC, BOUNDARY},
        answer_contains=["12,400", "escape of water"],
    ),
)
```

Expectations assert on **structure**, not prose. Asserting exact answer text produces a suite
that fails on every harmless rewording and gets disabled within a month.

## What to assert

```
 ┌────────────────────┬───────────────────────────────────────────────┐
 │ ASSERT ON          │ WHY                                           │
 ├────────────────────┼───────────────────────────────────────────────┤
 │ verdict            │ the decision, not the wording                 │
 │ warrant status     │ did evidence verification behave              │
 │ obligations        │ did the right gates fire                      │
 │ citations          │ did it cite the right sources                 │
 │ refusal reason     │ typed, so it is assertable                    │
 │ cost envelope      │ regressions in spend are regressions          │
 ├────────────────────┼───────────────────────────────────────────────┤
 │ DO NOT ASSERT      │                                               │
 │ exact answer text  │ brittle; suite gets disabled                  │
 └────────────────────┴───────────────────────────────────────────────┘
```

## Regression gates

```
   PR opened
      │
      ▼
   REPLAY_VERIFY over the golden set        (no model calls — fast, free)
      │
      ├── all match ──────────────▶ pass
      │
      └── any differ ─────────────▶ report the diff, block merge
                                    (a human decides if the change is intended)
   nightly
      │
      ▼
   REPLAY_BEHAVIOURAL over the golden set   (live calls — catches provider drift)
     policy=AS_AT_RUN                        so the model is the only variable
```

Splitting these matters. Structural regressions are caught free on every PR; behavioural
drift needs live calls and belongs on a schedule, not in the merge path.

## Metrics

```
   groundedness      % of claims with verified support
   citation accuracy % of citations that verify
   refusal rate      by reason — a spike is a signal, not a win
   hold rate         % reaching HOLD_FOR_APPROVAL
   calibration       stated confidence vs empirical accuracy
   cost per run      p50 / p95
   latency           p50 / p95, including verification overhead
```

**Refusal rate deserves a warning.** It is easy to optimise and easy to game: a system that
refuses everything scores perfectly on groundedness. Track refusal rate alongside groundedness
and treat a rise in either without a corresponding fall in the other as a regression.

## Calibration

For domains registering the `CALIBRATION` warrant, the harness produces the empirical figures
that warrant checks against.

```
   stated confidence   observed accuracy      verdict
   ──────────────────  ─────────────────      ────────────
   0.9 - 1.0           0.91                   well calibrated
   0.7 - 0.9           0.72                   well calibrated
   0.5 - 0.7           0.31                   OVERCONFIDENT  <- the finding
```

A model that says 0.6 and is right 31% of the time is more dangerous than one that refuses,
because a human downstream will trust the number.

## Owning the golden set

Golden sets live in the **domain package**, not the framework. The framework ships the
harness; the domain ships the cases. A framework that shipped medical golden cases would be
shipping medical knowledge, which [`../00-thesis.md`](../00-thesis.md) explicitly rules out.

## Related

- [`../concepts/conformance.md`](../concepts/conformance.md) — structural checks
- [`redteam.md`](redteam.md) — adversarial checks
- [`../runtime/replay.md`](../runtime/replay.md) — the execution mechanism
