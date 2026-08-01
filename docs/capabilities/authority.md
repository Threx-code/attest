# Authority — the authority warrant

**Was this permitted, for this actor, at this moment?**

## The mistake this avoids

The obvious design is an autonomy ladder. It was the design in several surveyed codebases,
and it does not survive contact with regulated domains.

```
   LADDER (too narrow)                  OBLIGATIONS (this design)
   ────────────────────────             ──────────────────────────────────
   class AutonomyLevel(Enum):           An action carries a SET of
       OBSERVE                          obligations, each of which must
       SUGGEST                          be discharged before it executes.
       ACT_WITH_APPROVAL
       ACT                              The ladder becomes four named
                                        preset compositions.
   Assumes: one approver,
   fixed rungs, no waiting              Expresses: dual control, n-of-m
   period, authority does not           quorum, cooling-off, amount-scaled
   scale with amount                    authority, reversibility gates
```

A bank needs dual control. A mortgage needs a cooling-off window during which the applicant
can withdraw. An insurer needs a second approver only above a payout threshold. None of
these are rungs on a ladder.

## The obligation protocol

```python
class Obligation(Protocol):
    name: str
    def discharge(self, action: Action, ctx: Context) -> Discharge: ...


class Discharge(StrEnum):
    SATISFIED = "satisfied"     # requirement met, proceed
    PENDING   = "pending"       # awaiting something external -> HOLD_FOR_APPROVAL
    FAILED    = "failed"        # cannot be met -> REFUSE
```

## Shipped obligations

```
 ┌────────────────────┬────────────────────────────────────────────────────┐
 │ CapabilityCheck    │ actor holds capability C  (confused-deputy defence) │
 │ Approval(n, roles) │ n approvals from the given roles; n>1 = quorum      │
 │ DualControl        │ two distinct humans; the actor may not self-approve │
 │ Budget             │ spend/volume ceiling for actor, tenant, or period   │
 │ CoolingOff(d)      │ d must elapse; the subject may cancel within it     │
 │ TimeWindow         │ only during permitted hours / before a deadline     │
 │ Notification       │ a party must be told before the action takes effect │
 │ ReviewAttestation  │ a named human attests they reviewed specific facts  │
 │ Reversibility      │ irreversible actions demand a strictly higher bar   │
 └────────────────────┴────────────────────────────────────────────────────┘
```

Obligations compose, and a domain supplies its own freely.

## How a domain expresses authority

The obligation set is a **function of the action**, which is what allows authority to scale:

```python
class InsuranceProfile(DomainProfile):
    def obligations_for(self, action, ctx) -> ObligationSet:
        if action.name != "settle_claim":
            return ObligationSet([CapabilityCheck(action.capability)])

        obligations = [
            CapabilityCheck("settle_claim"),
            Budget("daily_payout", ctx.actor),
        ]
        if action.amount > Money("10000", "GBP"):
            obligations.append(Approval(n=1, roles={"claims_manager"}))
        if action.amount > Money("100000", "GBP"):
            obligations.append(DualControl(roles={"claims_director"}))
        if action.involves_medical_evidence:
            obligations.append(ReviewAttestation("medical_officer"))
        return ObligationSet(obligations)
```

No framework code knows what a claim is, what GBP 10,000 means, or who a claims manager is.

## The discharge flow

```
   action proposed
        │
        ▼
   obligations_for(action, ctx)     <- domain decides
        │
        ▼
   ┌─────────────────────────────────────────────┐
   │  discharge each, in order, fail-fast        │
   │                                             │
   │   CapabilityCheck  -> SATISFIED             │
   │   Budget           -> SATISFIED             │
   │   Approval(1)      -> PENDING ───────────┐  │
   │   DualControl      -> (not evaluated)    │  │
   └──────────────────────────────────────────┼──┘
                                              │
              ┌───────────────────────────────┘
              ▼
        PendingAction opened
              │
              │   (out of band: a human decides)
              │
      ┌───────┴────────┐
      ▼                ▼
   approved         rejected / expired
      │                │
      ▼                ▼
   re-discharge     REFUSE
   ALL obligations
      │
      ▼
   still SATISFIED?  ──── no ──► REFUSE
      │ yes
      ▼
   execute effects
```

**Re-discharging every obligation after approval is not optional.** Between proposal and
approval the budget may have been exhausted, the actor's capability revoked, the evidence
gone stale. A system that only re-checks the approval is one that can be held open until the
other gates lapse.

## Pending actions

```python
@dataclass(frozen=True)
class PendingAction:
    id: ApprovalId
    action: Action
    attestation: Attestation        # the full case for the action
    obligations: Sequence[Obligation]
    expires_at: datetime            # never open-ended
    subject_summary: str            # what the approver sees
```

Two properties matter and are easy to get wrong:

- **`expires_at` is mandatory.** An approval queue without expiry becomes a backlog of
  half-executed decisions with no owner.
- **`subject_summary` is a first-class field, not a rendering concern.** The quality of a
  human approval is bounded by what the human is shown. An approver shown only "Approve
  payout GBP 12,400?" cannot meaningfully approve; one shown the evidence tree can. The
  framework requires the summary to exist; the domain decides what is in it.

## Budgets

Cost governance sits here rather than in the gateway, because "may this actor spend more"
is an authority question.

```
   Budget scopes                Enforced at
   ──────────────────           ──────────────────────────
   per actor                    obligation discharge
   per tenant                   (before the call, not after)
   per agent
   per period (day/month)
   per action class
```

Enforcing before the call is the distinction that matters: a budget checked after the LLM
call has already spent the money.

### Reserve, then commit — never merely read

A budget that is *read* and then acted on is a race. Two concurrent runs both read £20,000
remaining, both pass, and both spend £18,000.

```
   discharge  ──▶  RESERVE atomically        (fails if insufficient)
                        │
                   ┌────┴─────┐
                   ▼          ▼
               settle      abandon
                   │          │
                COMMIT     RELEASE
              actual cost   reservation
```

Reservations expire on the same short clock as the grant, so a crashed run cannot hold budget
indefinitely. This requires the host's `PolicyStore` to provide an atomic
compare-and-reserve; a store without transactions cannot satisfy the contract, and the port
documents that. See [`../assurance/threat-model.md`](../assurance/threat-model.md) attack 9.

## Related

- [`../concepts/verdicts.md`](../concepts/verdicts.md) — `HOLD_FOR_APPROVAL`
- [`../concepts/domain-profile.md`](../concepts/domain-profile.md) — `obligations_for`
- [`tools.md`](tools.md) — where obligations gate execution
- [`audit.md`](audit.md) — every discharge is an audit event
