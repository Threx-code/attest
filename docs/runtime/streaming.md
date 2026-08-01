# Streaming

## The conflict

```
   The framework verifies, THEN releases.
   Users expect tokens in ~300 ms.

   ┌──────────────────────────────────────────────────────┐
   │  verify-then-release:  silence ~3 s, then an answer   │
   │  release-then-verify:  fast, but ships unverified     │
   │                        content that may be retracted  │
   └──────────────────────────────────────────────────────┘
```

"It is high-stakes, so it can be slow" is not an argument anyone downstream accepts. The
alternative they choose is not a slower UI — it is a different framework.

## Resolution: two-phase release, gated by the profile

```
   model streams tokens
        │
        ▼
   ┌─────────────────────────────────────────────────┐
   │  PHASE 1 — PROVISIONAL                          │
   │    streamed to the consumer                     │
   │    marked provisional=true in every frame       │
   │    inbound guards ALREADY applied               │
   │    outbound streaming guards applied per chunk  │
   │    NO effects may execute                       │
   └─────────────────────────────────────────────────┘
        │
        ▼  generation completes
   ┌─────────────────────────────────────────────────┐
   │  PHASE 2 — SETTLED                              │
   │    evidence verified, warrants evaluated        │
   │    attestation emitted                          │
   │    verdict: ALLOW / WARNINGS / HOLD / REFUSE    │
   └─────────────────────────────────────────────────┘
        │
   ┌────┴──────────────┬────────────────────────┐
   ▼                   ▼                        ▼
  CONFIRMED         AMENDED                 RETRACTED
  provisional       corrected text          withdraw + reason
  text stands       replaces it             (typed refusal)
```

The consumer contract is explicit: **provisional frames are not an answer.** A client that
renders them as final is misusing the API, and the SDK makes that hard rather than easy —
provisional frames carry no attestation id, and the settled frame is the only one that does.

## What can stream, per tier

```
 ┌────────────────────────┬───────────────────────────────────────────────┐
 │ StreamPolicy.FORBIDDEN │ nothing streams; verify-then-release           │
 │                        │ clinical advice · adverse decisions · payments │
 ├────────────────────────┼───────────────────────────────────────────────┤
 │ StreamPolicy.GUARDED   │ streams, but only after per-chunk outbound     │
 │                        │ guards; retraction permitted                   │
 │                        │ most regulated interactive work                │
 ├────────────────────────┼───────────────────────────────────────────────┤
 │ StreamPolicy.FREE      │ streams with minimal per-chunk checks          │
 │                        │ internal ops · support · drafting              │
 └────────────────────────┴───────────────────────────────────────────────┘
```

Default is `FORBIDDEN`. A domain opts in per agent, and the framework refuses the combination
that is obviously unsafe:

```
   agent has tools with irreversible effects
     AND StreamPolicy != FORBIDDEN
     -> configuration error at construction
```

Effects never execute during phase 1, so a streamed answer cannot move money before it is
verified.

## The hazard, stated plainly

**A retracted statement was still read.** A clinician who read a provisional line about a drug
interaction has read it, whatever the retraction says afterwards. Retraction is a UI event,
not an undo.

```
   This is why FORBIDDEN is the default, and why
   tier-1 domains are expected to keep it.
```

Where streaming is permitted, the profile should require the consumer surface to render
provisional content visually distinctly — the framework can mark the frames; it cannot force
a frontend to honour the marking. That gap is real and is the reason the default is off.

## Per-chunk outbound guards

Streaming does not exempt output from the boundary warrant. A subset of guards runs per
chunk:

```
   RUNS PER CHUNK                  RUNS AT SETTLE ONLY
   ──────────────────────          ───────────────────────────
   PII leakage                     evidence verification
   secret / credential             entailment
   cross-tenant identifiers        completeness
   system-prompt extraction        warrant evaluation
```

A per-chunk guard failure **terminates the stream immediately** and settles as `REFUSE`. It
does not wait for generation to finish.

## Where the chunks come from

`StreamSession` governs a stream; it does not produce one. The tokens come from
[`ModelGateway.stream()`](../capabilities/llm-gateway.md), which applies residency, tier,
the breaker, the retry policy, the chain deadline and the idempotency key exactly as a
completion does, and the two meet here:

```python
session = StreamSession(spec)
tokens = gateway.session(context).stream(request)

try:
    for chunk in tokens:
        session.emit(chunk)          # per-chunk guards run on the way out
except StreamInterrupted as interrupted:
    session.terminate(interrupted.refusal)
```

Two failures, kept distinct on purpose:

- **`session.terminate(...)`** is *this* boundary refusing to let something out. The content
  was generated and must not be shown.
- **`StreamInterrupted`** is the provider dropping the connection after bytes had already
  been read. Nothing was refused; the answer is simply short. The exception carries the
  partial text so the caller can decide what to show, and the gateway deliberately does not
  fail over: re-emitting from a second provider makes the reader watch the answer start
  again, which is worse than watching it stop.

A reader that disconnects is neither. Closing the generator records the abandonment on the
run's `ModelCallLog`, because the provider kept generating and billing after the reader had
gone.

## Attestation shape is unchanged

Streaming adds fields; it does not change the artifact:

```python
streamed: bool
provisional_frames: int
settled_outcome: SettledOutcome    # CONFIRMED · AMENDED · RETRACTED
retraction: Refusal | None
```

Retraction rate is a monitored metric — see
[`../assurance/observability.md`](../assurance/observability.md). A rising rate means the
streaming policy is too permissive for that agent.

## Related

- [`../kernel/performance.md`](../kernel/performance.md) — deferred assurance, the related idea
- [`../capabilities/guards.md`](../capabilities/guards.md) — the guard set
- [`../concepts/verdicts.md`](../concepts/verdicts.md) — settling to a verdict
