# Banking

High volume, hard dual control, and the domain where an unauthorised effect moves money.

## 1. What is a claim?

> "This transaction pattern is consistent with structuring; recommend a SAR and a temporary
> hold on account 8823."

## 2. What supports it?

```
   "nine deposits of £9,400 in 11 days"   RecordValue (x9)
     ├── ledger records, pinned by id + version
     └── verify: re-query; amounts and timestamps must match

   "each below the £10,000 threshold"     QuotedSpan
     └── the reporting regulation text, versioned

   "risk score 0.91"                      Computation
     ├── model: aml_risk_v7
     └── verify: re-run over pinned inputs

   "consistent with structuring"          Derivation
```

Note the volume: nine `RecordValue` items for one modest claim. AML runs at millions of
decisions, which makes verification cost the dominant design constraint — the opposite of
[`medical.md`](medical.md).

## 3. What must be true before acting?

```python
def obligations_for(self, action, ctx):
    obs = [CapabilityCheck(action.capability), SanctionsScreen(ctx.subject)]

    if action.name == "freeze_account":
        obs += [
            DualControl(roles={"aml_officer"}),      # two distinct humans
            Notification("compliance", before_effect=True),
            TimeWindow(max_duration=days(5)),        # a hold that expires
        ]
    if action.name == "file_sar":
        obs += [
            Approval(n=1, roles={"mlro"}),
            TimeWindow(before=ctx.statutory_deadline),
            TippingOffGuard(),        # the subject must NOT be notified
        ]
    if EffectClass.FINANCIAL in action.effects:
        obs += [Budget("automated_holds", ctx.actor), Reversibility(action)]
    return ObligationSet(obs)
```

`TippingOffGuard` is worth pausing on. In most domains, notifying the subject is a
protection. In SAR filing it is a **criminal offence**. The same framework primitive —
`Notification` — is mandatory in one domain and forbidden in another, which is precisely why
obligation sets are domain-supplied rather than framework-defined.

## 4. What do the core four warrants miss?

```
   FAIRNESS          Do holds and SARs concentrate on protected groups?
                     A model trained on historical filings inherits
                     historical bias, and the feedback loop is closed:
                     more filings on a group -> more training signal.

   RECONCILIATION    Do the transactions cited actually sum to what the
                     narrative claims? A SAR that misstates amounts is
                     a defective filing.
```

## 5. What must a regulator be shown?

```
   the transaction set as it stood at decision time, the risk model
   version and its inputs, the regulation text cited, the dual-control
   record with both approver identities and timestamps, and the
   fairness screen
```

The dual-control record is often the first thing asked for and the most commonly
under-recorded — "approved by" with a single name and no timestamp is not evidence of dual
control.

## Warrant policy

```
   boundary         BLOCK    cross-tenant/customer leakage is catastrophic
   epistemic        BLOCK
   fairness         HOLD     concentration flagged -> human review
   reconciliation   BLOCK    on filings; WARN on internal triage
```

## The volume constraint

```
   millions of decisions/day
        │
        ├── entailment judging per claim   -> economically impossible
        ├── exact verification per claim   -> cheap, always on
        └── entailment on a sample + all   -> the workable policy
            escalated cases
```

A banking profile enables entailment only above a risk threshold and on a random sample.
That is a domain decision, and the framework must not impose the medical answer here.

## Tenancy vs customer scoping

Banking has two boundaries: tenant (which institution) and customer (whose data). Both are
enforced at retrieval, and the boundary warrant asserts both post-hoc. Conflating them is a
common and severe modelling error — see
[`../capabilities/guards.md`](../capabilities/guards.md).
