# Tools

**Actions an agent may propose — and the gates between proposal and effect.**

## Propose, verify, gate, grant, execute

The critical property: a model **proposes**; it never executes. Five distinct steps, each
able to stop the action.

```
   ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌────────┐  ┌─────────┐  ┌────────┐
   │  model   │─▶│  verify  │─▶│obligations│─▶│ ISSUE  │─▶│ execute │─▶│ record │
   │ proposes │  │ arguments│  │ discharge │  │ GRANT  │  │ effect  │  │ result │
   └──────────┘  └──────────┘  └───────────┘  └────────┘  └─────────┘  └────────┘
        │             │              │             │            │           │
    untrusted    context-       context-      bound to     the only    audit chain
                 deterministic  deterministic  action hash  side effect
                     │              │          + expiry
                     ▼              ▼          + nonce
                  REFUSE     HOLD_FOR_APPROVAL
```

Everything between the model and the effect is deterministic **over the captured execution
context** — not deterministic in general, since capability and budget checks read snapshotted
external state. See [`../kernel/execution-context.md`](../kernel/execution-context.md).

This is what makes a prompt injection that reaches the model unable to cause an unauthorised
effect on its own: the injection can change what is *proposed*, and cannot satisfy an
obligation or forge a grant.

## Tool specification

```python
@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: JSONSchema
    capability: Capability | None      # required to invoke
    reversible: bool                   # drives a stricter obligation set
    effects: frozenset[EffectClass]    # read · write · financial · external · physical
    idempotency: IdempotencyMode
```

`effects` and `reversible` are what let a profile write authority rules without enumerating
every tool:

```python
def obligations_for(self, action, ctx):
    obs = [CapabilityCheck(action.capability)]
    if EffectClass.FINANCIAL in action.effects:
        obs.append(Budget("payments", ctx.actor))
    if not action.reversible:
        obs.append(DualControl())          # applies to tools not yet written
    return ObligationSet(obs)
```

A tool added next year inherits the right gates by declaring its effects honestly.

## Argument verification

Schema validation is necessary and not sufficient. A well-formed argument can still be
wrong in a domain-specific way.

```
   ┌──────────────────┬──────────────────────────────────────────────┐
   │ schema           │ types, required fields, enums, ranges        │
   │ referential      │ does account 8823 exist, and belong to       │
   │                  │ this tenant?                                 │
   │ semantic         │ is this payment date in the past? is this    │
   │                  │ amount above the policy limit?               │
   │ consistency      │ do the arguments agree with the evidence     │
   │                  │ the model cited for proposing them?          │
   └──────────────────┴──────────────────────────────────────────────┘
```

The last one is the strongest and the least common. If the model cites a settlement
computation of GBP 12,400 and then proposes paying GBP 21,400, that is caught here —
deterministically, without another model call.

## Idempotency

Runs get retried; approvals get double-clicked; queues redeliver.

```python
class IdempotencyMode(StrEnum):
    NATURAL   = "natural"      # inherently safe to repeat (reads)
    KEYED     = "keyed"        # dedupe on a caller-supplied key
    FORBIDDEN = "forbidden"    # must never repeat; requires a keyed guard upstream
```

A `FORBIDDEN` tool without an idempotency key fails at registration, not at 2am.

## The registry

```python
registry.register(spec, executor)
registry.for_actor(actor)     # returns only tools the actor may invoke
```

`for_actor` filtering happens **before the model sees the tool list**. A tool the actor
cannot use is not advertised — which removes a whole class of confused-deputy attempts
rather than defending against them. Capability is then re-checked at discharge, because the
actor's grants may have changed mid-run.

## Executors are host code

The framework defines the protocol; the host writes the executor. Tool executors are where
domain logic lives, and none of it belongs in the framework.

```python
class ToolExecutor(Protocol):
    def execute(self, action: VerifiedAction, ctx: ExecutionContext) -> ExecutionResult: ...
```

> **Corrected.** An earlier version of this document said an executor *"must not re-check
> authority — it should assume it is only ever called after obligations are discharged."*
> That was wrong. It makes safety depend on executors only ever being called through the
> framework, and any host developer or future integration can call one directly.

The correct split:

```
   The executor must not DECIDE authority          (that stays in authority.md —
                                                    duplicating it creates two
                                                    places to get it wrong)

   The execution boundary MUST ENFORCE that a      (structural, not contractual)
   valid AuthorizationGrant exists
```

So execution goes through the kernel, which verifies the grant before the executor is ever
reached:

```python
kernel.execute(action, grant)      # not executor.execute(args, ctx)
```

Bypassing the framework now requires forging a grant bound to the exact action hash, rather
than simply calling a function. See [`execution.md`](execution.md).

## Related

- [`authority.md`](authority.md) — the gate between propose and execute
- [`guards.md`](guards.md) — why tool output is untrusted input
- [`../runtime/agents.md`](../runtime/agents.md) — declaring which tools an agent may use
