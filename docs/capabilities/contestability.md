# Contestability

`domains/mortgage.md` states that the system produces a counterfactual — *"declined because
commitments exceeded 45% of income; below 38% would have been approved."* This document is
how that is computed.

It is legally required in several target domains (adverse action notices, GDPR Art. 22,
FCA consumer duty), so a claim the design cannot cash is not acceptable.

## What contestability requires

```
   1. REASON        the specific factor that determined the outcome
   2. COUNTERFACTUAL what would have to change to alter it
   3. RECOURSE      what the subject can do about it
   4. CONSISTENCY   the reason given matches the internal record
```

Item 4 is what an ombudsman actually tests. Two different explanations for the same decision —
one internal, one to the subject — is the finding they look for.

## The counterfactual is computed deterministically, or not at all

This is the design decision that makes it tractable. **The framework does not ask a model to
explain a decision.** A model-generated explanation is a plausible story, not a cause, and in
a regulated setting a plausible story is a liability.

```
   ┌──────────────────────────────────────────────────────────────┐
   │  Counterfactuals are computed over the DETERMINISTIC part    │
   │  of the decision — the FunctionNodes, rules, and thresholds  │
   │  — never over the model's reasoning.                         │
   └──────────────────────────────────────────────────────────────┘
```

```
   decision
     ├── deterministic: affordability calc, LTV, policy thresholds
     │        │
     │        └──▶ INVERTIBLE — a counterfactual is exact and provable
     │
     └── model judgement: document interpretation, narrative
              │
              └──▶ NOT INVERTIBLE — reported as a contributing factor,
                   never as a counterfactual
```

If the determining factor was a model judgement rather than a rule, the honest output is:

> "This application was referred for manual review because the submitted documents could not
> be automatically interpreted."

not an invented threshold.

## Three mechanisms, in order of preference

```
 ┌───┬──────────────────────┬──────────────────────────────────────────────┐
 │ 1 │ RULE ATTRIBUTION     │ the binding constraint is identified directly│
 │   │                      │ from the rule that failed. Exact, free.      │
 │   │                      │ "commitments 45% > threshold 38%"            │
 ├───┼──────────────────────┼──────────────────────────────────────────────┤
 │ 2 │ BOUNDARY SEARCH      │ binary search on the single binding input    │
 │   │                      │ over the deterministic model. Exact, cheap   │
 │   │                      │ (~15 evaluations, no model calls).           │
 │   │                      │ "below 38.2% would have been approved"       │
 ├───┼──────────────────────┼──────────────────────────────────────────────┤
 │ 3 │ FACTOR RANKING       │ where several inputs interact, rank by       │
 │   │                      │ sensitivity. Approximate, and LABELLED as    │
 │   │                      │ "principal factors", not as a threshold.     │
 └───┴──────────────────────┴──────────────────────────────────────────────┘
```

Mechanisms 1 and 2 require the profile to expose its decision rules as inspectable
`FunctionNode`s rather than opaque code — which is a strong reason to keep deterministic logic
out of the model in the first place, as
[`../runtime/composition.md`](../runtime/composition.md) argues on other grounds.

## The warrant

```python
CONTESTABILITY = WarrantKind("contestability")

@dataclass(frozen=True)
class ContestabilityReport(WarrantReport):
    kind = CONTESTABILITY
    determining_factors: Sequence[Factor]     # ranked, with values
    counterfactual: Counterfactual | None     # exact, or None
    counterfactual_method: Method             # RULE · BOUNDARY · RANKING · NONE
    recourse: Sequence[RecourseOption]
    subject_message: str
    internal_reason: str
    consistent: bool                          # subject_message ⊆ internal_reason
```

`consistent` is machine-checked: every factor cited to the subject must appear in the
internal record. A subject message asserting a reason absent from the internal reason fails
the warrant.

## When it cannot be produced

```
   counterfactual_method == NONE
        │
        ▼
   profile policy for adverse decisions
        │
        ├── BLOCK  -> the decision cannot be issued automatically
        │             (mortgage, insurance decline, benefits refusal)
        │
        └── HOLD   -> routed to a human who supplies the reason
```

**A decision that cannot be explained is not automated.** That is the correct behaviour, and
it is enforced rather than advised. It also creates the right incentive: a domain that wants
automation keeps its determining logic deterministic and inspectable.

## Related

- [`../domains/mortgage.md`](../domains/mortgage.md) — the claim this now supports
- [`../runtime/composition.md`](../runtime/composition.md) — `FunctionNode`
- [`../concepts/verdicts.md`](../concepts/verdicts.md) — `subject_message`
