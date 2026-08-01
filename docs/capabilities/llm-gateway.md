# LLM gateway

**One call site for every model interaction.** Providers, resilience, cost, and drift all
live behind it.

```
   agent ──▶ ┌─────────────────────────────────────────────┐ ──▶ provider
             │              GATEWAY                        │
             │  redact ─ cache ─ budget ─ breaker ─ retry   │
             │     │       │       │        │        │      │
             │     │       │       │        │        └─ failover
             │     │       │       │        └────────── open on repeated failure
             │     │       │       └─────────────────── refuse before spending
             │     │       └─────────────────────────── semantic + exact
             │     └─────────────────────────────────── PII never leaves
             └─────────────────────────────────────────────┘
                                  │
                                  ▼
                       every call -> audit chain
```

Nothing calls a provider SDK directly. That rule is what makes cost, redaction, and drift
detection possible at all — each was reimplemented per-call-site in the surveyed codebases,
and therefore inconsistently.

## Provider port

```python
class LLMProvider(Protocol):
    name: str
    def complete(self, req: CompletionRequest) -> CompletionResponse: ...
    def supports(self, feature: Feature) -> bool: ...   # tools, json_mode, vision, caching, streaming


class StreamingProvider(LLMProvider, Protocol):
    def stream(self, req: CompletionRequest) -> Generator[str, None, CompletionResponse]: ...
```

Shipped as optional extras: Anthropic, OpenAI, Bedrock, Azure OpenAI, Vertex, and a
dependency-free local embedding provider for tests and air-gapped deployments.

`supports()` exists so the gateway can refuse a request a provider cannot honour rather than
silently degrading it — a failover that drops tool-calling support mid-run is worse than an
error.

## Resilience

```
   attempt 1 ── fail ──▶ retry (backoff+jitter) ── fail ──▶ failover provider
                                                                  │
                              breaker opens after N failures ◀────┘
                                       │
                                       ▼
                        fast-fail for the cooldown window
                        (no thundering herd on a degraded provider)
```

Failover crosses providers, which means the response may come from a different model than
requested. That fact is **recorded in the attestation**, because a decision made by a
fallback model is a materially different decision, and replay must know.

### One deadline bounds the whole chain

`RetryPolicy` bounds attempts per provider. `total_deadline` bounds the chain, and without
it the timeouts multiply: an SDK's own retries, times the retry policy, times every
candidate. A single logical call can then hold a provider for minutes while each layer
believes it is being patient on its own small budget.

```python
ModelGateway(providers, pricing=..., clock=..., total_deadline=timedelta(seconds=45))
```

`None` by default, so a deployment that has not thought about it gets exactly the previous
behaviour. Checked before each provider and before each backoff sleep - the sleep is where
the time goes, and backing off only to find the budget spent spends the budget on waiting.

Running out of time is `deadline_exceeded`, not `evidence_source_unreachable`. The remedies
differ: "every provider failed" sends an operator to look at routing, and the routing was
fine.

Read from the injected `Clock`, whose contract already requires monotonicity within a run.
That keeps a deadline reproducible in replay rather than making it the ambient wall-clock
time this package bans everywhere else.

### Streaming

`ModelGateway.stream()` applies every rule `call()` applies - residency, tier, features, the
breaker, the retry policy, the deadline, the idempotency key and the cache - and yields
tokens instead of returning a body. It exists because a call site that cannot stream through
the gateway streams around it, and then cost, residency and failover go back to being things
that call site remembers on its own.

Streaming is a `Feature`, so a backend that did not declare `supports_streaming` is filtered
out of a streamed request the same way one that did not declare tools is, and a chain with
nothing left refuses.

**Failover happens only before the first chunk.** Once bytes have reached the reader,
switching provider means re-emitting from the top, and watching the answer start again is
worse than watching it stop. After the first chunk a failure is `StreamInterrupted`, which
carries the partial text and a `stream_interrupted` refusal.

A reader that disconnects mid-stream is recorded on `ModelCallLog.streams_abandoned`, not
priced as a zero-cost call. The provider generated tokens and billed for them and nobody in
the process learned how many, which is the `UNKNOWN` case this framework refuses to coerce
to a number - `ModelCallLog.complete()` is then `False`, so anything reconciling against an
invoice is told the total is short rather than left to assume it is whole.

## Cost

Every call is priced and attributed. Budget enforcement happens at
[`authority.md`](authority.md) — the gateway measures, the obligation layer decides.

```
   CostRecord
     input_tokens / output_tokens / cached_tokens
     model, provider, whether it was a failover
     usd  (from a versioned pricing table)
     attributed to: actor · tenant · agent · run
```

The pricing table is versioned and pinned into the attestation. Prices change; a
historical cost figure that silently re-prices at today's rate is not an audit record.

## Drift detection

The capability none of the surveyed systems have, and the one that matters most for
long-lived regulated systems.

```
   Problem: providers change model behaviour under a stable name.
            Your prompt is pinned. Your model id is pinned.
            The behaviour is not.

   Detection:
     a canary set of frozen prompts runs on a schedule
                      │
                      ▼
     outputs compared against recorded baselines
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
     within tolerance        drift detected
          │                       │
       record                  alert + record
                               a version marker so
                               later attestations are
                               distinguishable from
                               earlier ones
```

Without this, "the model changed under us" is discovered through a support ticket months
later, with no way to tell which decisions were affected.

## Caching

```
   exact       identical request -> stored response      always safe
   semantic    similar request  -> stored response       domain-gated
```

Semantic caching is **off by default** and must be enabled per domain. Returning a
near-miss cached answer is acceptable for a support chatbot and unacceptable for a claim
adjudication. The framework will not make that choice on a domain's behalf.

Cache entries are invalidated by a corpus epoch marker, so a document update invalidates
answers derived from it rather than serving stale support.

## Related

- [`../kernel/ports.md`](../kernel/ports.md) — the provider protocol
- [`authority.md`](authority.md) — budget enforcement
- [`../runtime/replay.md`](../runtime/replay.md) — pinning models for re-execution
