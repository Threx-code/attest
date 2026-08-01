# Execution

**The boundary where a decision becomes an effect in the world.**

This is the layer an earlier draft of this architecture did not have, and its absence was the
most serious production-safety gap. Everything else in the framework proves a decision was
warranted. This proves the *effect* corresponded to the decision — and admits when it cannot.

## The scenario that forces this design

```
   Praxis                    Bank API
     │                          │
     │──── transfer £100,000 ──▶│
     │                          │  payment COMMITTED
     │◀──── (timeout) ──────────│
     │
     ▼
   process crashes
     │
     ▼
   no execution event recorded

   ─────────────────────────────────────────
   Bank says:   the payment happened.
   Praxis says: no execution event exists.
```

And the mirror image:

```
   Praxis records:  EXECUTED £100,000
   Bank API:        request timed out; payment never made
```

Neither `ALLOW` nor `REFUSE` is a truthful answer here. The system does not know.

## Effect lifecycle

```
   PROPOSED ──▶ AUTHORIZED ──▶ SUBMITTED ──▶ ACKNOWLEDGED ──▶ COMMITTED
      │              │              │              │
      │              │              │              └──▶ FAILED
      │              │              │
      │              │              └────────────────▶ UNKNOWN   ◀── the
      │              │                                    │          important
      │              └──▶ REFUSED                         │          one
      │                                                   ▼
      └──▶ REFUSED                                   reconciliation
                                                     (out of band)
                                                          │
                                              ┌───────────┴──────────┐
                                              ▼                      ▼
                                          COMMITTED               FAILED
```

`UNKNOWN` is a **terminal state for the run** and a **work item for reconciliation**. It is
never silently coerced. A run that ends `UNKNOWN` produces an attestation saying so, and the
verdict is neither `ALLOW` nor `REFUSE` — it is `UNKNOWN`, which callers must handle.

```python
class EffectState(StrEnum):
    PROPOSED = "proposed"; AUTHORIZED = "authorized"; SUBMITTED = "submitted"
    ACKNOWLEDGED = "acknowledged"; COMMITTED = "committed"
    FAILED = "failed"; REFUSED = "refused"; UNKNOWN = "unknown"
```

**Write the intent before the effect.** `SUBMITTED` is persisted *before* the external call,
so a crash leaves evidence that a call was in flight. Without this, `UNKNOWN` is
indistinguishable from "never attempted."

## Authorization grants

Re-discharging obligations after approval is necessary and **not sufficient**. There is still
a gap between the last check and the effect:

```
   10:00:00  capability check      PASS
   10:00:01  approval              PASS
   10:00:02  budget check          PASS
   10:00:03  capability REVOKED            ◀── nothing observes this
   10:00:04  execute()                     ◀── proceeds anyway
```

The fix is a grant: a token bound to the exact action, issued only after every obligation
discharges, and verified at the effect boundary.

```python
@dataclass(frozen=True)
class AuthorizationGrant:
    grant_id: GrantId
    action_hash: Hash          # binds to THESE arguments, not this tool
    actor: ActorRef
    tenant: TenantRef
    tool: str
    policy_version: str
    profile_version: str
    evidence_snapshot: Hash
    approvals: Sequence[ApprovalRef]
    issued_at: datetime
    expires_at: datetime       # short — seconds to minutes, not hours
    nonce: Nonce               # single-use; replay is detected
```

```
   verify args ──▶ discharge obligations ──▶ ISSUE GRANT ──▶ execute(grant, action)
                                                                    │
                                             ┌──────────────────────┘
                                             ▼
                          the boundary checks, before any effect:
                            grant.action_hash == hash(action)      exact arguments
                            grant not expired
                            grant not revoked
                            grant.nonce unused                      no replay
                            grant.policy_version still current
```

`action_hash` covers the **arguments**, not just the tool name. A grant for
"pay £12,400 to beneficiary X" cannot authorise "pay £500,000 to beneficiary Y."

## Enforcement is structural, not contractual

An earlier version of `tools.md` said *"an executor must not re-check authority — that is the
obligation layer's job."* That was wrong. It makes safety depend on executors only ever being
called through the framework.

```
   WRONG                              RIGHT
   ─────────────────────────          ────────────────────────────────
   executor.execute(args, ctx)        kernel.execute(action, grant)
                                          │
   Any host code can call this            ├── verifies the grant
   directly and bypass every gate.        └── then invokes the executor
                                              with an ExecutionContext
   Safety rests on a convention.           that PROVES authorisation.

                                      Bypassing means forging a grant,
                                      not merely calling a function.
```

The executor still must not **decide** authority — that stays in the obligation layer, and
duplicating it creates two places to get it wrong. But it cannot **act** without a grant.

## Effect semantics

`reversible: bool` is too coarse for these domains. A regulatory filing cannot be un-sent,
but it can be amended — that is neither reversible nor irreversible.

```python
@dataclass(frozen=True)
class EffectSemantics:
    reversible: bool             # can be undone, restoring prior state
    compensatable: bool          # cannot be undone, but a corrective action exists
    externally_visible: bool     # a third party has already observed it
    financially_material: bool
    legally_binding: bool
    idempotent_upstream: bool    # the EXTERNAL system honours an idempotency key
    transactional: bool          # participates in a transaction we control
```

```
   ┌──────────────────────┬───────┬────────┬──────────┬───────────┐
   │ EFFECT               │ revers│ compens│ ext. vis │ binding   │
   ├──────────────────────┼───────┼────────┼──────────┼───────────┤
   │ update internal flag │  yes  │  yes   │   no     │   no      │
   │ send email           │  no   │  yes   │  yes     │   no      │
   │ regulatory filing    │  no   │  yes   │  yes     │  yes      │
   │ payment              │  no   │ maybe  │  yes     │  yes      │
   │ account freeze       │  yes  │  yes   │  yes     │  yes      │
   └──────────────────────┴───────┴────────┴──────────┴───────────┘
```

Profiles write obligation rules against these fields rather than enumerating tools, so a tool
written next year inherits the right gates by declaring its semantics honestly.

## Idempotency has two levels

```
   FRAMEWORK DEDUPLICATION            EFFECT-LEVEL IDEMPOTENCY
   ──────────────────────────         ─────────────────────────────────
   we will not submit twice           the EXTERNAL system will not
                                      apply it twice
   Under our control.                 Requires the upstream to honour
                                      the key. Many do not.
```

```
   Praxis: submit payment, key=123
   Bank:   ignores the key
   Praxis: timeout
   Praxis: retry, key=123
   Bank:   TWO PAYMENTS
```

So `idempotent_upstream` is a property of the **integration**, asserted per tool. Retry policy
is a function of *both* levels — `ToolSpec.idempotency` (may we resubmit) and
`idempotent_upstream` (will they deduplicate):

```
 ┌──────────────────────┬─────────────────────┬──────────────────────────────┐
 │ ToolSpec.idempotency │ idempotent_upstream │ ON TIMEOUT                   │
 ├──────────────────────┼─────────────────────┼──────────────────────────────┤
 │ NATURAL              │ either              │ retry                        │
 │ KEYED                │ True                │ retry with the same key      │
 │ KEYED                │ False               │ UNKNOWN -> reconciliation    │
 │ FORBIDDEN            │ either              │ UNKNOWN -> reconciliation    │
 └──────────────────────┴─────────────────────┴──────────────────────────────┘
```

The two middle rows are where duplicate payments come from. A `KEYED` tool looks safe to
retry — we hold an idempotency key — but the key only helps if the upstream honours it.
Deciding retry from `ToolSpec.idempotency` alone is the bug; this table is a unit test, not a
guideline.

Retrying a non-idempotent financial effect after a timeout is how duplicate payments happen.
The framework refuses to do it. `IdempotencyMode` is defined in [`tools.md`](tools.md).

## Reconciliation

`UNKNOWN` effects need an out-of-band resolver, because only the external system knows.

```
   UNKNOWN effect
        │
        ▼
   reconciliation queue        (durable; survives restarts)
        │
        ├── query the external system by our idempotency key
        ├── operator inspection where no query exists
        │
        ▼
   resolve to COMMITTED or FAILED
        │
        ▼
   append to the audit chain, supersede the attestation
```

Reconciliation lag is an SLO, not a background detail: an `UNKNOWN` £500,000 transfer
outstanding for a week is an incident.

## Partial failure in flows

A flow whose third node commits an irreversible effect and whose fourth fails leaves the
world partially changed. `runtime/composition.md` validates statically against the worst
shapes, but at runtime:

```
   effect committed, later node fails
        │
        ├── compensatable  -> run the compensating action, record BOTH
        ├── not compensatable -> flow ends INCOMPLETE, not FAILED
        │                        (the effect is real; pretending otherwise
        │                         is the lie)
        └── always -> the attestation records exactly which effects
                      committed and which did not
```

`INCOMPLETE` is deliberately distinct from `FAILED`. "Nothing happened" and "some of it
happened" require different human responses.

## Related

- [`authority.md`](authority.md) — discharging obligations, which precedes the grant
- [`tools.md`](tools.md) — proposal and argument verification
- [`audit.md`](audit.md) — effect events and sealing
- [`../runtime/composition.md`](../runtime/composition.md) — partial failure across nodes
