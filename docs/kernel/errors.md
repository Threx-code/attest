# Errors and refusals

`Refusal` (a verdict) and the exception hierarchy cover adjacent ground. Without a rule, the
boundary gets decided inconsistently per call site — and in a framework built on fail-closed
behaviour, an inconsistent boundary is a safety problem.

## The rule

```
   ┌──────────────────────────────────────────────────────────────────┐
   │  A REFUSAL is a decision the system made.                        │
   │  An EXCEPTION is the system being unable to decide.              │
   │                                                                  │
   │  If an attestation can be produced, it is a refusal.             │
   │  If it cannot, it is an exception.                               │
   └──────────────────────────────────────────────────────────────────┘
```

That test is mechanical and settles every case.

```
   evidence does not support the claim     -> REFUSE   (we decided)
   actor lacks capability                  -> REFUSE   (we decided)
   budget exhausted                        -> REFUSE   (we decided)
   injection detected                      -> REFUSE   (we decided)
   evidence source unreachable             -> REFUSE   (we decided we
                                                        cannot proceed)
   ──────────────────────────────────────────────────────────────────
   config invalid at startup               -> EXCEPTION (no run exists)
   port implementation returns garbage     -> EXCEPTION (contract broken)
   audit sink unwritable                   -> EXCEPTION (cannot record,
                                                         so cannot proceed)
   profile version unloadable              -> EXCEPTION
```

The near-miss cases are instructive. **An unreachable evidence source is a refusal** — the
system is working, the world is not cooperating, and that is a decision worth recording with
its full context. **An unwritable audit sink is an exception** — we cannot produce a record,
so we must not act at all.

## Exception hierarchy

```
   AttestError
     ├── ConfigurationError      invalid config, profile, or flow spec
     │     └── (always at startup or construction, never mid-run)
     ├── ContractViolation       a port broke its documented obligation
     │     ├── AuditSinkError        cannot append, or not append-only
     │     ├── StoreError            cannot persist an attestation
     │     └── RetrieverScopeError   returned out-of-tenant results
     ├── IntegrityError          chain, seal, or signature failure
     └── KernelError             internal invariant violated
```

**Nothing in this hierarchy is catchable by domain code.** Profiles and tools handle
refusals; exceptions propagate to the host, which fails the request. A domain that catches
`ContractViolation` and continues has defeated the guarantee.

## Fail-closed applies to both

```
   an exception ANYWHERE in the assurance path
        │
        ▼
   the run does NOT complete
   no effect executes
   what was recorded stays recorded
```

An earlier finding from the surveyed codebases was `except Exception: return True` inside a
guard. The rule that prevents its recurrence:

```
   Guards, verifiers, and obligations MUST NOT catch broad exceptions.
   An error inside one is an UNSATISFIED warrant, surfaced, never a pass.

   Enforced by lint: no bare `except:` or `except Exception:` in
   attest/guards, attest/evidence, attest/authority.
```

## Refusal taxonomy is open; exceptions are closed

```
   RefusalReason     open — domains register their own
                     (a domain has reasons we cannot enumerate)

   AttestError       closed — the framework's failure modes are
                     ours to know and finite
```

A domain that wants a new exception type wants a refusal reason instead.

## Partial completion is neither

A flow whose third node committed an irreversible effect and whose fourth failed is not a
refusal and not an exception:

```
   verdict = INCOMPLETE
     effects_committed: [...]
     effects_not_attempted: [...]
     reason: <what failed>
```

`INCOMPLETE` is distinct because "nothing happened" and "some of it happened" require
different human responses. See
[`../capabilities/execution.md`](../capabilities/execution.md).

## Related

- [`../concepts/verdicts.md`](../concepts/verdicts.md) — the refusal side
- [`ports.md`](ports.md) — the contracts whose violation raises
- [`../capabilities/guards.md`](../capabilities/guards.md) — fail-closed
