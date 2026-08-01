# Judging

Entailment judging uses a model to check a model. That is circular trust, and the circularity
has to be designed rather than assumed away.

## The problem

```
   generator   "The exclusion does not apply."
        │
        ▼
   judge       "Is that claim entailed by the cited evidence?"
        │
        ▼
   verdict     "Yes."          <- and now the epistemic warrant
                                  says SATISFIED, confidently
```

If the judge is wrong, the warrant is wrong — and it is wrong in the most damaging way, by
producing a verified-looking attestation.

Worse: **a judge from the same model family fails in correlated ways with the generator.** The
inference that fooled the writer tends to fool the reader. Sampling the same model twice
measures consistency, not correctness.

## Three rules

```
 ┌───┬────────────────────────────────────────────────────────────────────┐
 │ 1 │ CROSS-FAMILY BY DEFAULT                                            │
 │   │ the judge must come from a different MODEL family than the         │
 │   │ generator. Same-family judging is a configuration error unless     │
 │   │ explicitly overridden and recorded in the attestation.             │
 ├───┼────────────────────────────────────────────────────────────────────┤
 │ 2 │ JUDGES ARE CALIBRATED, AND THE CALIBRATION IS PUBLISHED            │
 │   │ a judge's agreement with human adjudication is measured in the     │
 │   │ eval harness, per domain, and carried on every verdict it emits.   │
 ├───┼────────────────────────────────────────────────────────────────────┤
 │ 3 │ JUDGE OUTPUT IS PROBABILISTIC AND LABELLED AS SUCH                 │
 │   │ never merged into the same field as exact verification.            │
 └───┴────────────────────────────────────────────────────────────────────┘
```

### Family means the weights, not the vendor

An earlier draft of rule 1 said *provider* family. That is the wrong axis, and
open-weight serving makes the difference concrete:

```
   Groq · Bedrock · Vertex · Together    all serve LLAMA
        │
        ▼
   three different PROVIDERS
   one MODEL family
        │
        ▼
   a Llama-on-Groq judge for a Llama-on-Bedrock generator passes a
   provider check and is same-family judging in disguise — it measures
   consistency, which is exactly what rule 1 exists to prevent
```

So the constraint is on the weights. `ModelRef` therefore carries a `family` the
gateway resolves from the model id, and the cross-family check compares families
rather than provider names. Two entries in the same family are same-family however
they were routed.

The inverse also holds and is useful: **one provider can supply several families.**
Bedrock serves Llama, Mistral and Claude; a panel drawn entirely from Bedrock can
still be genuinely cross-family. Requiring different providers would have refused a
valid panel while permitting an invalid one. See ADR 0041.

Rule 3 is the one that keeps the whole epistemic warrant honest:

```
   SupportResult
     supported: bool
     confidence: float | None      <- None means EXACT verification
                                      a float means a JUDGE decided
     judge: JudgeRef | None        <- which model, which calibration
```

A reviewer can always tell whether "supported" was established mechanically or by opinion.
Conflating them is how "verified" comes to mean nothing.

## Panel judging where it matters

For high-materiality claims, one judge is not enough.

```
   claim
     │
     ├──▶ judge A  (family 1)  ─┐
     ├──▶ judge B  (family 2)  ─┼──▶ aggregate
     └──▶ judge C  (family 3)  ─┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
          unanimous              majority              split / no majority
              │                      │                      │
          SATISFIED            SATISFIED with          UNSATISFIED
                               a dissent finding       -> profile policy
                                                          (usually HOLD)
```

**Disagreement is recorded, never discarded.** A 2-1 split on whether an exclusion applies is
exactly the signal a human reviewer needs, and averaging it away destroys it.

## Adversarial framing

A judge asked *"is this supported?"* is biased toward yes. The prompt asks the opposite:

```
   WEAK      "Does the evidence support the claim?"
   STRONG    "Find the strongest reason this claim is NOT supported by
              the cited evidence. If you cannot find one, say so."
```

Default to `refuted` under uncertainty. This is the same principle as fail-closed guards, and
it materially changes measured judge behaviour on the "real quote, wrong inference" family in
[`../assurance/redteam.md`](../assurance/redteam.md).

## Cost gating — resolves ADR 0011

Entailment is a model call per claim. The policy is a function of materiality, not a global
setting:

```python
def entailment_policy(self, claim, ctx) -> EntailmentPolicy:
    if ctx.materiality == HIGH:   return EntailmentPolicy.PANEL(n=3)
    if claim.is_negative:         return EntailmentPolicy.SINGLE   # "does not apply"
    if ctx.sampled:               return EntailmentPolicy.SINGLE
    return EntailmentPolicy.NONE
```

```
   NONE      exact verification only            THIN / STD tiers
   SINGLE    one cross-family judge             FULL tier, sampled
   PANEL(n)  n judges, disagreement recorded    high materiality
   DEFERRED  judged after response, warrant     reversible effects only
             finalised async
```

**The default is `NONE`**, deliberately. Defaults get inherited unexamined, and a default that
adds a model call per claim would make the framework uneconomical everywhere before anyone
evaluated it. A domain opts *up*.

Negative claims default to `SINGLE` even when sampling would skip them — asserting that
something does *not* apply has no quote to verify against, so exact verification cannot help.

## Judges are not correctness

Restating the boundary from
[`../concepts/assurance-boundaries.md`](../concepts/assurance-boundaries.md):

```
   A judge improves SUPPORT assurance.
   It does not establish CORRECTNESS.
   A well-supported claim can still be wrong.
```

## Related

- [`evidence.md`](evidence.md) — exact verification, the non-probabilistic half
- [`../assurance/eval.md`](../assurance/eval.md) — where judge calibration is measured
- [`../kernel/performance.md`](../kernel/performance.md) — tier gating
