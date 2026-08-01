# Determinism

**A design constraint, not a feature.** Replay, drift detection, and reproducible evaluation
all depend on it, and all of them break silently when it is violated.

## The three rules

```
   ┌─────────────────────────────────────────────────────────────────┐
   │  1. NO AMBIENT TIME                                             │
   │     datetime.now() / time.time() are banned in the core.        │
   │     Time arrives through the injected Clock port.               │
   ├─────────────────────────────────────────────────────────────────┤
   │  2. NO AMBIENT RANDOMNESS                                       │
   │     random / uuid4 are banned. Ids come from a seeded           │
   │     IdGenerator; sampling seeds are captured.                   │
   ├─────────────────────────────────────────────────────────────────┤
   │  3. NO AMBIENT CONFIG                                           │
   │     No module-level reads of environment or settings.           │
   │     Everything arrives through AttestConfig.                    │
   └─────────────────────────────────────────────────────────────────┘
```

Each is enforced by a lint rule in CI, because each is a one-line violation that nothing else
detects and that quietly disables replay for every agent downstream.

## Why a single violation is expensive

```
   a prompt template renders datetime.now() into its body
                     │
                     ▼
   the rendered content differs on every call
                     │
                     ▼
   the content hash differs on every call
                     │
                     ▼
   prompt versioning is meaningless
   replay never reproduces
   eval baselines never match
                     │
                     ▼
   ...and nothing errors. It just stops working.
```

The correct form passes the clock through context, so the value is captured and replayable:

```python
render(template, ctx={"today": clock.now(), ...})
```

## What is captured

```
   ┌──────────────────────────────────────────────────────────────┐
   │  clock value at dispatch                                     │
   │  id generator seed                                           │
   │  model sampling parameters (temperature, top_p, seed)        │
   │  prompt fragment hashes                                      │
   │  domain profile version                                      │
   │  pricing table version                                       │
   │  evidence content hashes                                     │
   │  tool call arguments and results, verbatim                   │
   └──────────────────────────────────────────────────────────────┘
```

## What cannot be made deterministic

Honest limits:

- **Model sampling.** Even at temperature 0, providers do not guarantee bit-identical output
  across time or infrastructure. `REPLAY_HISTORICAL` and `REPLAY_VERIFY` avoid this by not
  calling the model at all; `REPLAY_BEHAVIOURAL` with `policy=AS_AT_RUN` measures the
  difference rather than pretending it is zero.
- **External tool results.** A live API returns what it returns. Replay uses the recorded
  result, which is why replay is read-only.
- **Wall-clock-dependent domain logic.** "Is this within the cooling-off period" genuinely
  depends on now. Injected clock makes it *controllable*, not constant.

## Testing

The conformance kit runs every domain profile twice with a frozen clock and a fixed seed,
and asserts the attestations are identical. That is the only reliable way to catch a
determinism violation, because the symptom is silent.

## Related

- [`ports.md`](ports.md) — `Clock`, `IdGenerator`
- [`../runtime/replay.md`](../runtime/replay.md) — what determinism buys
- [`../capabilities/prompts.md`](../capabilities/prompts.md) — content addressing
