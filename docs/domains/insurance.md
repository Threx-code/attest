# Insurance

Document-shaped evidence meets computed settlements — the domain closest to the "obvious"
design, which makes it a useful control case.

## 1. What is a claim?

> "Claim CL-8823 is payable at £12,400 under section 4.2; the escape-of-water exclusion does
> not apply."

## 2. What supports it?

```
   "policy covers escape of water"      QuotedSpan
     ├── policy wording PW-2019, §4.2, chars 1180-1244
     └── verify: substring present at offset in that document version

   "excess is £250"                     RecordValue
     └── policy record 8823, field `excess`, version 7

   "settlement = £12,400"               Computation
     ├── model: settlement_calc v2.1
     ├── inputs: damage estimate, excess, depreciation
     └── verify: re-run; must reproduce

   "exclusion does not apply"           Derivation
     └── over the wording and the loss adjuster's Observation
```

The last claim is a **negative**: asserting something does *not* apply. Negative claims are
harder to ground than positive ones — no quote says "this exclusion does not apply." The
support is an inference over what the exclusion says and what happened.

A profile should require negative claims to cite the exclusion text they are ruling out,
so a reviewer can check the reasoning rather than trusting it.

## 3. What must be true before acting?

```python
def obligations_for(self, action, ctx):
    if action.name != "settle_claim":
        return ObligationSet([CapabilityCheck(action.capability)])

    obs = [CapabilityCheck("settle_claim"), Budget("daily_payout", ctx.actor)]
    if action.amount > Money("10000", "GBP"):
        obs.append(Approval(n=1, roles={"claims_manager"}))
    if action.amount > Money("100000", "GBP"):
        obs.append(DualControl(roles={"claims_director"}))
    if action.involves_medical_evidence:
        obs.append(ReviewAttestation("medical_officer"))
    if action.decision == Decision.DECLINE:
        obs.append(ComplaintRightsNotice(ctx.policyholder))
    return ObligationSet(obs)
```

Authority scales with amount — three different gates on the same action type. A four-rung
ladder assigns one level per agent and cannot express this.

## 4. What do the core four warrants miss?

```
   CONTESTABILITY      A declined claimant has ombudsman rights. The
                       decline reason must be specific enough to contest
                       and must match what the internal record says.
                       Two different messages for the same decision is
                       exactly what an ombudsman looks for.

   TEMPORAL_VALIDITY   Policy wording changes at renewal. The wording in
                       force ON THE DATE OF LOSS governs — not today's.
                       Citing the current wording for a 2019 loss is a
                       verifiable citation and a wrong decision.
```

`TEMPORAL_VALIDITY` here is subtler than "is this stale." It is "is this the version that
applied at the relevant time," where the relevant time is the loss date, not now. The
domain's `validity()` answers against the loss date because only the domain knows that rule.

## 5. What must an ombudsman be shown?

```
   bundle/
     attestation.json
     evidence/
       PW-2019.pdf              the wording in force at the loss date
       policy-record-8823.json  as at decision time
       settlement-calc.json     inputs and output, re-runnable
       adjuster-report.pdf
     chain.jsonl                including the approval, with approver + timestamp
     VERIFY.md
```

## Warrant policy

```
   epistemic         BLOCK
   contestability    BLOCK    on DECLINE
   temporal          BLOCK    <- stricter than most domains, because the
                              wrong wording version is a wrong decision,
                              not merely a stale one
   boundary          BLOCK
```

## Why this domain is the control case

Insurance is the closest fit to a naive document-and-citation design, and it still needs
`Computation` evidence, amount-scaled obligations, and two warrants outside the core four.

If the domain nearest to the obvious design still exceeds it, the obvious design was never
sufficient — which is the argument for the generalisations in
[`../capabilities/evidence.md`](../capabilities/evidence.md) and
[`../capabilities/authority.md`](../capabilities/authority.md).
