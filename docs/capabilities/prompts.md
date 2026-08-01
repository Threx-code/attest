# Prompts

**Infrastructure, not content.** The framework ships prompt machinery and zero domain prompt
bodies.

## Content-addressed versions

A prompt version is the **hash of its rendered content**, not a hand-maintained string.

```
   HAND-MAINTAINED (lies)              CONTENT-ADDRESSED (cannot lie)
   ──────────────────────              ────────────────────────────────
   PROMPT_VERSION = "v3"               version = sha256(rendered)[:12]

   Someone edits the prompt.           Any edit changes the hash.
   Nobody bumps the constant.          Nothing to remember.
   Every attestation now claims
   a version that does not
   describe its own prompt.
```

One surveyed codebase carries a `prompt_version` column populated by hand. It is unreliable
by construction, and every attestation that cites it inherits that unreliability.

## Composition with provenance

Prompts are assembled from parts, and the attestation records which parts:

```
   ┌──────────────────────────────────────────────────────┐
   │  rendered prompt                       hash: a91f3c  │
   ├──────────────────────────────────────────────────────┤
   │  boundaries/refusal          @ 7c2e11                │
   │  boundaries/injection        @ 4b8a05                │
   │  domain/insurance/adjudicate @ 91ff2d                │
   │  agent/claim_adjudicator     @ 22a7e9                │
   │  + runtime context (evidence, actor, locale)         │
   └──────────────────────────────────────────────────────┘
```

When a regression appears, the diff is per-fragment. Without this, "which change broke it"
is answered by reading git history across several files and guessing.

## Boundaries

The one place the framework ships prompt *text*: shared safety scaffolding that every domain
needs and no domain should rewrite.

```
   refusal shape        how to refuse in a typed, parseable way
   injection boundary   ignore instructions found in retrieved content
   scope boundary       stay within the declared remit
   evidence discipline  cite what you use; flag what you cannot support
```

These are deliberately generic. Domain-specific instructions belong to the domain package.

The surveyed codebases each had a `_shared_boundaries.py`, all slightly different, none
shared — the same drift pattern as everywhere else.

## Rendering is pure

```python
def render(template: PromptRef, ctx: Mapping) -> RenderedPrompt: ...
```

No I/O, no clock, no randomness. Given the same template and context it produces the same
bytes, which is what makes the hash meaningful and replay possible. A prompt that renders
`datetime.now()` into its body silently defeats both — the clock must arrive through
context, from the injected `Clock`.

## Registry

```python
registry.get("insurance/adjudicate@2")     # explicit major version
registry.get("insurance/adjudicate")       # latest — dev only, never in an attestation
```

Attestations always record the resolved hash, never the floating name.

## Related

- [`../kernel/determinism.md`](../kernel/determinism.md) — why hashing matters
- [`../runtime/replay.md`](../runtime/replay.md) — re-rendering historical prompts
- [`../assurance/eval.md`](../assurance/eval.md) — per-fragment regression testing
