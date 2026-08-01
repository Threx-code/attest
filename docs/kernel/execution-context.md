# Execution context

**Everything after model proposal is deterministic *over a captured context* — not
deterministic in general.**

An earlier draft claimed the post-proposal layer was simply "deterministic." That claim does
not survive review, and the corrected version is stronger.

## Why the original claim was wrong

```
   Steps described as "deterministic":

     referential verification   -> does account 8823 exist?      external state
     capability check           -> does the actor hold C?        external state
     budget check               -> spend remaining?              external state
     record verification        -> field F still equals X?       external state
     retrieval                  -> which chunks come back?       external state
```

Every one depends on state outside the run. Same input, different moment, different result.
That is not determinism — and under adversarial review, an overstated determinism claim
discredits the parts that are genuinely sound.

## The corrected claim

```
   ┌──────────────────────────────────────────────────────────────┐
   │  Given a captured ExecutionContext, every post-proposal      │
   │  step is a pure function of that context.                    │
   │                                                              │
   │  verify(context)  is deterministic.                          │
   │  verify()         is not.                                    │
   └──────────────────────────────────────────────────────────────┘
```

This is defensible, testable, and sufficient for replay.

## What is captured

```python
@dataclass(frozen=True)
class ExecutionContext:
    clock: datetime                      # single snapshot; monotonic within the run
    config: AttestConfig
    profile: ProfileRef                  # name + version
    policy_snapshot: PolicySnapshot      # obligation rules as at dispatch
    identity_snapshot: IdentitySnapshot  # actor, capabilities, tenant, as at dispatch
    evidence_snapshot: EvidenceSnapshot  # retrieved items + content hashes
    tool_specs: Mapping[str, Hash]       # tool definitions in force
    model: ModelRef                      # provider, id, params, seed,
                                         # and training_attestation (see below)
    prompts: Mapping[str, Hash]          # every fragment
    pricing_version: str
    corpus_epochs: Mapping[str, str]     # per-corpus version markers
    seed: int
    framework_version: str               # ours; drives the verification path
    flow_spec_version: str | None        # pinned for the life of a suspended run
    tenant_binding: TenantBinding        # profile, config and residency for this tenant

    def content_hash(self) -> Hash: ...  # the whole context, hashed as one unit
```

`ModelRef` carries a nullable `training_attestation: RunId | None`, which is what lets an
inference run reach the provenance of the model that produced it — see
[`../capabilities/lineage.md`](../capabilities/lineage.md). `None` is the honest value for a
third-party API model whose training data we cannot attest to, and it must never be read as
"trained on nothing".

The last three fields exist so that the context alone carries everything
[`versioning.md`](versioning.md) requires to reconstruct a run. Together with the fields above
them, that is all nine of its recorded axes — held in one hashed object rather than as nine
loose fields on the attestation, which can drift apart from each other. See
[`../concepts/attestation.md`](../concepts/attestation.md).

```
   dispatch
      │
      ▼
   CAPTURE CONTEXT ◀──── one moment; everything read here, once
      │
      ▼
   all downstream steps read ONLY from the context
      │
      ▼
   attestation embeds the context hash
```

## The rule that makes it work

> **After capture, no component reads live external state.**

A capability check reads `identity_snapshot`, not the identity service. A budget check reads
`policy_snapshot` and the run's own accumulated spend. Anything that must be live — an
external balance at the moment of payment — is an **effect-boundary** concern and belongs in
[`../capabilities/execution.md`](../capabilities/execution.md), guarded by a short-lived authorization grant,
not a context read.

```
   CONTEXT-TIME                     EFFECT-TIME
   ─────────────────────            ──────────────────────────────
   snapshot, deterministic          live, non-deterministic
   verification, warrants           the external call itself
   obligation discharge             grant validity re-check
                                    (seconds, not minutes)
```

That split is what lets verification be reproducible while the effect remains correct against
a world that moves.

## Snapshot staleness is a real risk

A long-running or suspended flow may act on a context captured days earlier.

```
   context captured  ──────── 6 days ────────▶  approval granted
                                                       │
                                    ┌──────────────────┤
                                    ▼                  ▼
                            re-capture context   re-verify evidence
                            (identity, policy,   against the NEW
                             budget)              snapshot
```

`runtime/composition.md` requires re-discharge on resume; this is the mechanism. The
attestation records **both** contexts, so a reviewer can see what changed between proposal
and execution.

## Consequences for replay

Replay modes are defined in terms of which parts of the context are reused — see
[`../runtime/replay.md`](../runtime/replay.md). The context is what makes those modes
meaningful rather than aspirational.

## Enforcement

```
   lint      no live-state reads in verification code paths
   test      run twice with an identical context -> identical attestation
   test      run twice with a DIFFERENT context -> difference is explainable
             by the context diff alone
```

The second test is the valuable one: it proves nothing hidden leaked into the computation.

## Related

- [`determinism.md`](determinism.md) — the three no-ambient rules
- [`../runtime/replay.md`](../runtime/replay.md) — three replay modes
- [`../capabilities/execution.md`](../capabilities/execution.md) — effect-time
