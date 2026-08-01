# Mortgage

The domain that breaks the autonomy ladder, and where a wrong answer is a discrimination
claim.

## 1. What is a claim?

> "This application is affordable at £1,840/month and meets lending policy; recommend
> approval at 4.6% over 25 years."

## 2. What supports it?

```
   "net income £4,200/month"        RecordValue
     └── payslip record, verified via open banking, 3 months

   "affordability = £1,840"         Computation
     ├── model: affordability_v3.2
     ├── inputs pinned: income, commitments, stress rate 8.0%
     └── verify: re-run the model; output must reproduce exactly

   "property valued at £340,000"    Observation
     ├── surveyor SR-882, RICS, inspected 2026-06-30
     └── validity: 90 days  <- expires

   "LTV 78% within policy"          Derivation
```

`Computation` verification is the interesting one: re-running `affordability_v3.2` over the
pinned inputs must reproduce £1,840 exactly. If the model was retrained, it will not — and
that is a genuine finding, not a false alarm.

## 3. What must be true before acting?

Here the ladder fails completely:

```python
def obligations_for(self, action, ctx):
    obs = [CapabilityCheck("underwrite"), FairnessScreen(ctx.applicant)]

    if action.name == "issue_offer":
        obs += [
            Approval(n=1, roles={"underwriter"}),
            CoolingOff(days=7, cancellable_by=ctx.applicant),   # <- not a rung
            Notification("applicant", before_effect=True),
        ]
    if action.decision == Decision.DECLINE:
        obs += [AdverseActionNotice(ctx.applicant)]             # <- legally required
    if action.amount > Money("1000000", "GBP"):
        obs += [DualControl(roles={"lending_director"})]
    return ObligationSet(obs)
```

```
   OBSERVE / SUGGEST / ACT_WITH_APPROVAL / ACT
       cannot express:
         - a 7-day window during which the applicant may withdraw
         - an obligation that fires only on DECLINE
         - two distinct humans above a threshold
         - a notification that must precede the effect
```

An obligation set expresses all four. This is the concrete argument in
[`../capabilities/authority.md`](../capabilities/authority.md).

## 4. What do the core four warrants miss?

```
   FAIRNESS           Does the decision differ by protected characteristic,
                      holding financial facts constant?
                      Proxy discrimination is the real risk: postcode
                      correlates with ethnicity. Nobody wrote a rule; the
                      model found the correlation.

   CONTESTABILITY     Can the applicant be told why, specifically enough
                      to contest it? An adverse action notice saying "the
                      model declined you" is not compliant.
                      Requires a counterfactual:
                        "declined because commitments exceeded 45% of
                         income; below 38% would have been approved"
```

`CONTESTABILITY` requires the system to compute what *would* have changed the outcome. That
is a capability the four core warrants have no reason to provide, and it is mandatory here.

## 5. What must a regulator be shown?

```
   the decision, its evidence tree, the fairness screen result,
   the counterfactual, the model version, and the policy version
   in force on the decision date
```

The last is why profile versioning matters. Change the stress rate and every historical
decision must still be verifiable against the policy that actually applied.

## Warrant policy

```
   fairness         BLOCK    a failed screen never reaches an applicant
   contestability   BLOCK    on DECLINE — cannot decline without a reason
   contestability   RECORD   on APPROVE — no notice needed
   epistemic        BLOCK
   temporal         HOLD     valuation older than 90 days
```

Note `contestability` is `BLOCK` on decline and `RECORD` on approve. Warrant policy is a
function of the action, not a fixed table.

## Jurisdiction

`MortgageProfile(jurisdiction="UK")` vs `"NG"` differ in protected characteristics,
cooling-off duration, and notice requirements — same shape, different data. See
[`../concepts/domain-profile.md`](../concepts/domain-profile.md) on why this is a parameter
rather than a separate profile.
