# Versioning and compatibility

Four independent version axes interact. For a system whose selling
point is verifying decisions years later, *"can we still load profile 1.2?"* is a first-order
question, and an earlier draft had no answer.

## The axes

```
   framework   x   profile   x   prompt   x   model
      │              │            │            │
      │              │            │            └── provider-controlled;
      │              │            │                may change under a
      │              │            │                stable name
      │              │            └── content-addressed; immutable
      │              └── domain-controlled; semver
      └── ours; semver
```

Plus, in practice: `config`, `pricing table`, and `corpus epoch` — all pinned into the
attestation, all part of what a replay must reconstruct.

## The rule that makes this tractable

```
   ┌──────────────────────────────────────────────────────────────────┐
   │  An attestation is verifiable for as long as its profile         │
   │  version can be loaded. Everything else is pinned by content     │
   │  hash and needs no code to resolve.                              │
   └──────────────────────────────────────────────────────────────────┘
```

Prompts are content-addressed, so they are self-describing. Models are recorded, not
re-executed, for `REPLAY_VERIFY`. Config is embedded. **Only the profile is executable code
that must still exist.** That reduces four axes to one supported surface.

## Profile support window

```
   profile version    supported for verification
   ──────────────────────────────────────────────────────────
   current            yes
   previous major     yes
   older              yes, IF the domain publishes it as an
                      archived profile package

   the domain owns the window, and it must be at least as long
   as the retention period in storage.md
```

The framework enforces the coupling at configuration time:

```
   retention_period > profile_support_window
        -> configuration error

   otherwise you retain attestations you can no longer verify,
   which is worse than not retaining them
```

## Framework compatibility

```
 ┌────────────────┬──────────────────────────────────────────────────────┐
 │ PATCH  x.y.Z   │ no behaviour change. Attestations byte-identical.    │
 │ MINOR  x.Y.0   │ additive only. Old attestations verify unchanged.    │
 │                │ New warrant kinds may appear on NEW runs only.       │
 │ MAJOR  X.0.0   │ may change verification semantics. MUST ship a       │
 │                │ compatibility shim that verifies prior-major         │
 │                │ attestations, for at least the retention period.     │
 └────────────────┴──────────────────────────────────────────────────────┘
```

The major-version obligation is the expensive one and it is non-negotiable: a framework
upgrade that silently invalidates historical attestations destroys the product's core claim.

```
   verify(attestation)
        │
        ├── attestation.framework_version == current  -> native path
        └── older major                               -> shim path
                                                          (tested in CI
                                                           against a corpus
                                                           of frozen
                                                           attestations)
```

A **frozen attestation corpus** is kept in the repo: real attestations from every supported
major, verified on every build. This is the only reliable way to notice that a refactor broke
historical verification.

## Suspended flows

A deploy during a suspended flow is the sharp edge.

```
   flow suspended on framework 2.3, profile 2.1.0, flow spec v7
        │
        │   ... deploy to framework 2.4, profile 2.2.0 ...
        │
        ▼
   resume
        │
        ├── flow spec        PINNED to v7          (composition.md)
        ├── profile          PINNED to 2.1.0
        ├── framework        CURRENT, but must satisfy MINOR rules
        └── if the framework moved a MAJOR:
               the flow cannot resume automatically
               -> HOLD, escalate for explicit migration
```

Automatic resumption across a major boundary is refused. Half a decision made under one set
of semantics and half under another is not defensible, and a human should decide whether to
migrate or restart it.

## Downgrade protection

A version downgrade is an attack, not just an operational error — it can reinstate a weaker
policy.

```
   profile version in the binding  <  version already used for this tenant
        │
        ▼
   REFUSED, audit event: policy_downgrade
   (an explicit, recorded override is required)
```

Same for framework major and for corpus epochs. See
[`../assurance/redteam.md`](../assurance/redteam.md) family 9.

## What is recorded on every attestation

```
   framework_version   profile@version    config_hash
   prompt_hashes       model + params     pricing_version
   corpus_epochs       flow_spec_version  tenant_binding_hash
```

Nine fields. Together they make a run reconstructible without guessing, which is the whole
requirement.

## Related

- [`storage.md`](storage.md) — retention, which bounds the support window
- [`../runtime/replay.md`](../runtime/replay.md) — what each version axis affects
- [`../runtime/composition.md`](../runtime/composition.md) — flow spec pinning
