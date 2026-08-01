# Verdicts

Every run resolves to exactly one of six outcomes.

```python
class Verdict(StrEnum):
    # --- reachable without attempting an effect ---
    ALLOW               = "allow"
    ALLOW_WITH_WARNINGS = "allow_with_warnings"
    HOLD_FOR_APPROVAL   = "hold_for_approval"
    REFUSE              = "refuse"
    # --- reachable only after an effect was attempted ---
    UNKNOWN             = "unknown"      # effect attempted; outcome not established
    INCOMPLETE          = "incomplete"   # some effects committed; the flow did not finish
```

Unlike `WarrantKind`, this **is** a closed enum, and the value of a closed set here is that
every call site can be exhaustively checked.

That guarantee only holds if every *reachable* outcome is a member. An earlier draft of this
document declared four, while [`../capabilities/execution.md`](../capabilities/execution.md)
described a run terminating `UNKNOWN` and [`../kernel/errors.md`](../kernel/errors.md)
described one terminating `INCOMPLETE`. Both are reachable. A four-arm `match` over a
six-outcome space is precisely the silent-drop failure this document exists to prevent — so
the enum carries all six. See ADR 0033.

```python
match att.verdict:
    case Verdict.ALLOW:               ship(att)
    case Verdict.ALLOW_WITH_WARNINGS: ship_flagged(att)
    case Verdict.HOLD_FOR_APPROVAL:   queue(att)
    case Verdict.REFUSE:              explain(att)
    case Verdict.UNKNOWN:             reconcile(att)     # NOT success, NOT failure
    case Verdict.INCOMPLETE:          triage(att)        # some of it happened
    case _ as unreachable:            assert_never(unreachable)
```

`assert_never` makes an omitted arm a type error rather than a runtime surprise.

## Verdict is not EffectState

The two are related and distinct, and conflating them is a modelling error:

```
   Verdict       what the CALLER must handle — one value, always present
   EffectState   the effect lifecycle — PROPOSED .. COMMITTED / FAILED /
                 UNKNOWN, per effect, only where an effect exists
```

A run may commit one effect and leave another `UNKNOWN`; the `EffectState` values differ per
effect, while the run's `Verdict` is `INCOMPLETE`. Callers match on the verdict; reconciliation
and audit work from `EffectState`. See
[`../capabilities/execution.md`](../capabilities/execution.md).

## The state machine

```
                         ┌──────────────┐
                         │   dispatch   │
                         └──────┬───────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
     boundary guard      warrants evaluated   obligations
     rejects input       unsatisfied          undischarged
              │                 │                 │
              ▼                 ▼                 ▼
         ┌────────┐      ┌────────────┐    ┌──────────────────┐
         │ REFUSE │      │ policy says│    │ HOLD_FOR_APPROVAL│
         └────────┘      │ BLOCK/WARN │    └────────┬─────────┘
                         └─────┬──────┘             │
                               │                    │ human decides
                    ┌──────────┴─────────┐          │
                    ▼                    ▼          ├──── approved ──┐
              ┌────────┐    ┌──────────────────┐    │                │
              │ REFUSE │    │ALLOW_WITH_WARNING│    └── rejected ──┐ │
              └────────┘    └──────────────────┘                   │ │
                                                                   ▼ ▼
                                              ┌────────┐    ┌──────────┐
                                              │ REFUSE │    │  ALLOW   │
                                              └────────┘    └──────────┘
                                                                  │
                                                                  ▼
                                                            effects execute
                                                                  │
                                    ┌─────────────────────────────┼──────────────┐
                                    ▼                             ▼              ▼
                              all committed              no outcome        some committed,
                                    │                    established        flow failed
                                    ▼                             ▼              ▼
                              ┌──────────┐               ┌──────────┐    ┌────────────┐
                              │  ALLOW   │               │ UNKNOWN  │    │ INCOMPLETE │
                              └──────────┘               └──────────┘    └────────────┘
                                                          reconciliation   triage; the
                                                          (out of band)    effects are real
```

The two right-hand outcomes are the ones a four-state model has to lie about. A timed-out
payment is not `ALLOW` and not `REFUSE`, and a flow that committed three of five irreversible
effects is neither. See [`../capabilities/execution.md`](../capabilities/execution.md).

## `HOLD_FOR_APPROVAL` is the important one

Human-in-the-loop is a **first-class verdict**, not an exception and not a `None`.

This is the single most important shape decision in the framework. One surveyed codebase
had built the machinery — pending tool calls, approve/reject services — but modelled it as a
side channel. The consequence is that call sites can forget it exists:

```
   AS A SIDE CHANNEL                   AS A VERDICT
   ─────────────────────────           ────────────────────────────────
   result = agent.run(...)             att = agent.run(...)
   # returns None when held            match att.verdict:
   # caller may not check                  case ALLOW:      ship(att)
   # -> action silently dropped            case HOLD:       queue(att)
   #    or, worse, treated as done         case REFUSE:     explain(att)
                                           case WARNINGS:   ship_flagged(att)
                                           case UNKNOWN:    reconcile(att)
                                           case INCOMPLETE: triage(att)
                                     # type checker enforces exhaustiveness
```

In a mortgage or claims system, "silently dropped" and "treated as done" are both incidents.

## Refusals are typed, never prose

A refusal must be machine-readable, because refusal rates are a monitored metric and
refusals often trigger downstream obligations (an adverse action notice, an escalation).

```python
@dataclass(frozen=True)
class Refusal:
    reason: RefusalReason        # open taxonomy — domains extend
    warrant: WarrantKind | None  # which warrant failed, if any
    detail: str                  # human-readable, never the sole record
    subject_message: str | None  # what the end user may be told (may differ)
```

The `subject_message` split matters in regulated domains: what you tell the applicant is
often constrained by law and differs from the internal reason.

```
   RefusalReason — core taxonomy (open, domains extend)
   ───────────────────────────────────────────────────────
   unsupported_claim        epistemic warrant unsatisfied
   out_of_scope             outside the agent's declared remit
   insufficient_authority   actor lacks capability
   budget_exhausted         spend ceiling hit
   injection_detected       boundary warrant
   unsafe_action            domain-defined hazard
   stale_evidence           temporal validity expired
   ...plus domain-registered reasons
```

## Warnings are not free

`ALLOW_WITH_WARNINGS` ships the answer *and* the findings. It exists so that a domain can
distinguish "imperfect but usable" from "unusable" — but it carries an obligation of its own:
the host must surface warnings to whoever acts on the answer.

A reporting agent that emits an unreconciled figure with a warning, into a dashboard that
renders only the figure, has produced a material misstatement with a clean conscience. The
framework can only make the warning available; see
[`../adapters/django.md`](../adapters/django.md) for the serialiser contract that keeps it
attached.

## Related

- [`attestation.md`](attestation.md) — the carrier
- [`warrants.md`](warrants.md) — what produces a verdict
- [`../capabilities/authority.md`](../capabilities/authority.md) — the hold/approve lifecycle
