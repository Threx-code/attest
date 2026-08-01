# Approvals at scale

Human-in-the-loop is correct and creates a throughput ceiling
unrelated to compute. Worse, an approval obligation reliably discharged without genuine review
**manufactures evidence of oversight** — which is worse than having no obligation at all.

## The failure mode

```
   400 approvals/day per reviewer
        │
        ▼
   ~45 seconds each
        │
        ▼
   rubber-stamping
        │
        ▼
   the authority warrant is SATISFIED on every run
   and means nothing
        │
        ▼
   in an enforcement review, the records show diligent
   oversight of decisions nobody actually reviewed
```

The framework cannot force attention. It can shape the queue so that attention is *possible*,
and it can **measure** whether review is real.

## Risk-based routing

Not every action needs the same review. The profile maps actions to review depth:

```
 ┌──────────────────┬────────────────────────────────────────────────────┐
 │ AUTO             │ no human; obligations discharge mechanically       │
 │ SAMPLED          │ n% routed to review; the rest auto                 │
 │                  │ sampling is RANDOM and unpredictable to the actor  │
 │ REVIEW           │ every instance reviewed by one approver            │
 │ DUAL             │ two distinct humans                                │
 │ PANEL            │ n-of-m, for the highest materiality                │
 └──────────────────┴────────────────────────────────────────────────────┘
```

```python
def review_depth(self, action, ctx) -> ReviewDepth:
    if action.amount > Money("100000", "GBP"):  return ReviewDepth.DUAL
    if action.amount > Money("10000", "GBP"):   return ReviewDepth.REVIEW
    if ctx.actor.is_new or ctx.anomaly_score > 0.7:
        return ReviewDepth.REVIEW
    return ReviewDepth.SAMPLED(rate=0.05)
```

Sampling must be **unpredictable to the proposing actor**, or it becomes a gap to route around.
The sample decision is made by the framework, seeded per-run, and recorded.

## Batching without collapsing review

Batching is necessary at volume and dangerous done naively — a "approve all 200" button makes
the warrant meaningless.

```
   SAFE BATCHING                        UNSAFE
   ─────────────────────────            ────────────────────────────
   group by SIMILARITY, and             group by arrival, approve all
   surface the OUTLIERS first
                                        Every item looks the same;
   ┌───────────────────────────┐        the reviewer sees none of them.
   │ 47 routine claims         │
   │   £180-£420, same peril,  │
   │   all within policy       │──▶ batch approve permitted
   ├───────────────────────────┤
   │ 3 requiring attention     │
   │   - unusual peril         │
   │   - excess mismatch       │──▶ individual review REQUIRED
   │   - new broker            │
   └───────────────────────────┘
```

The framework computes the split; the profile supplies the similarity and anomaly functions.
Batch approval is only offered for the homogeneous group, and the batch's composition is
recorded in every member's attestation.

## Queue discipline

```
   PRIORITISED BY DEADLINE, not arrival
        │
        ├── statutory deadline approaching   -> escalate
        ├── expires_at approaching           -> escalate then expire
        └── SLA breach                       -> alert

   NEVER unbounded:
        every PendingAction has expires_at
        expiry is a REFUSE with reason approval_expired,
        never a silent drop
```

Delegation and out-of-office are first-class, because an approver on leave is otherwise a
stalled queue:

```python
Delegation(from_role="claims_manager", to_role="deputy",
           window=DateRange(...), max_amount=Money("50000", "GBP"))
```

Delegations are themselves authority changes — recorded, bounded, and visible in the
attestation of anything they authorised.

## Measuring whether review is real

This is the part that keeps the warrant honest.

```
   MONITORED SIGNALS                    WHAT A BAD VALUE MEANS
   ───────────────────────────          ────────────────────────────────
   time-to-decision distribution        a spike at <5s = not reading
   approval rate by reviewer            100% = not discriminating
   rate on INJECTED control items       the strongest signal
   evidence-expanded rate               did they open the tree at all?
   post-hoc reversal rate               approvals later found wrong
```

**Control items** are the sharpest instrument: a small, known rate of synthetic actions that
*should* be rejected, injected into the queue. A reviewer who approves them is not reviewing.
This is standard practice in screening professions and it transfers directly.

```
   control item approved
        │
        ▼
   reviewer's approvals flagged for audit
   the finding is recorded, not hidden
```

Control items must be clearly synthetic in the record so they never produce a real effect —
they are refused at the execution boundary regardless of approval.

## Capacity as a first-class constraint

A profile that routes more actions to review than the organisation can staff is
misconfigured, and the framework can say so before it becomes a backlog:

```
   projected review volume  vs  declared reviewer capacity
        │
        ▼
   exceeds capacity  ->  warn at configuration time
                         report in observability
```

## Related

- [`authority.md`](authority.md) — the obligation this scales
- [`../assurance/observability.md`](../assurance/observability.md) — the signals
- [`../concepts/verdicts.md`](../concepts/verdicts.md) — `HOLD_FOR_APPROVAL`
