# Attest — a governed control plane for AI actions

Agents, rules engines, scheduled jobs and humans may **propose** actions. The kernel
decides whether a consequential effect may execute, and produces a record that the
decision was warranted — verifiable offline, years later, against the policy and
evidence that actually applied at the time.

```
        ┌───────────── Intelligence ──────────────┐
        │  agents · models · retrieval · humans   │
        └────────────────────┬────────────────────┘
                             │  propose
                             ▼
        ┌─────────────────────────────────────────┐
        │            CONTROL KERNEL               │
        │  evidence   completeness   authority    │
        │  boundary   provenance     execution    │
        └────────────────────┬────────────────────┘
                             │  authorised effect
                             ▼
        ┌─────────────────────────────────────────┐
        │   external systems · money · people     │
        └─────────────────────────────────────────┘
```

## The core invariant

> No consequential effect executes without a kernel-issued authorization grant bound to
> the exact action — its arguments, not merely its tool name.

Bypassing the framework therefore means forging a grant, not calling a function.

## What this does *not* establish

Stated first, because getting it wrong is this design's most dangerous failure mode.

Attest **cannot** establish that a decision was *correct*, and any surface implying
otherwise is misrepresenting it. What it establishes is narrower and honest:

> "This decision was made from these sources, under this policy version, authorised by
> these parties, and here is the complete record."

A beautifully verifiable attestation of a wrong decision is entirely possible — the
wrong policy version for the loss date, the right record for the wrong person, a
correct citation supporting a wrong inference. See
[`docs/concepts/assurance-boundaries.md`](docs/concepts/assurance-boundaries.md), which
separates the six distinct assurances and marks which are strong, which are weak, and
which are not provable at all.

## Status

**Pre-release.** All five layers exist and every gate is green. Not on PyPI yet — install
from a pinned commit (see [Installation](#installation)) — and the API may change until
1.0.

| Layer | State |
|---|---|
| **L0 kernel** | Complete — canonical hashing, the attestation codec, verdicts, warrants, evidence, effects, actions, grants, hash-chained audit, execution context, attestation, config, ports |
| **L1 capabilities** | Complete — evidence, completeness, authority, execution, reconciliation, audit, guards, memory, judging, witness, approvals, gateway, prompts, lineage, profiles |
| **L2 runtime** | Complete — the `RunEngine` entry point, agent specs, scope, delegation, flows, routing, replay, streaming |
| **L3 assurance** | Complete — conformance kit, ten red-team families, evidence export |
| **L4 adapters** | In-memory and SQLite stores; seven provider backends; Django models, migrations, stores, serialisers, dispatch and read views, admin and commands |
| Specification (`docs/`) | Complete — 90 documents, 42 ADRs |

**Providers.** Anthropic, Claude-on-Vertex, Gemini (on Vertex or the Developer API),
OpenAI (Azure is a parameter, not a second class), Bedrock via the Converse API, Groq,
and a dependency-free deterministic backend for conformance runs and air-gapped
deployments. Each imports its SDK inside a method, so the base install still pulls
nothing. Refusals, content filters and empty completions raise rather than being
recorded as answers, and the *weights* family — not the vendor — is what the
cross-family judging rule compares.

**The run entry point.** `RunEngine.execute()` takes one proposal and returns one
sealed attestation. The ordering is the guarantee: warrants are evaluated before a
grant is issued, and the grant is issued before the executor is reachable. A pipeline
that ran the effect and assembled warrants afterwards would produce an equally handsome
record of an unauthorised action.

**A durable record.** `AttestationCodec` round-trips an attestation to canonical bytes
and back, and **decoding verifies the content hash** — a payload altered in the database
or a codec that drifted from the value objects fails at read time rather than coming
back as a plausible record that says something else. That is also what lets
`verify_audit_chain` recompute event hashes rather than trusting the stored linkage.

**The gateway.** `ModelGateway` is the only thing that calls a provider. Residency is
read from the tenant binding rather than passed in, so the boundary every attestation
records is the one that actually filtered the providers. Retry precedes failover, the
circuit breaker fast-fails a degraded provider, exact caching is invalidated by corpus
epoch, and `DriftCanary` catches a model changing under a stable name. Budget
enforcement stays in the obligation layer: the gateway measures, the obligation layer
decides.

**How the guarantees are verified.** Every claim above is a test, and the checks that
matter most are the ones that fail when a control is present but never reached:

| Gate | What it refuses to let through |
|---|---|
| `pytest` | 1,517 tests, 90% coverage floor, including races and fault injection |
| `scripts/check_reachability.py` | a security-relevant method with no caller anywhere |
| `scripts/check_class_design.py` | behaviour that belongs on the value it concerns |
| `scripts/check_docs_consistency.py` | a capability document with no module behind it |
| `import-linter` | a layer reaching for one above it |
| `mypy --strict` | over `src/` **and** `tests/` |
| `pytest -m redteam` | eighteen adversarial proposals, executed against a real engine |
| CI matrix | Python 3.11–3.13 · Linux, macOS, Windows · SQLite, PostgreSQL 17, MySQL 8.4 |
| `make check` | reproducible build, clean-environment install, docs build |

The database matrix is not decoration. The append-only audit chain and immutable
attestations are enforced by **triggers**, not by application code — "we only ever
INSERT" is a convention, and conventions decay — so the trigger DDL is executed against
each supported vendor on every run rather than reviewed and assumed.

The red-team corpus is executed rather than declared. A case without an `attack` callable
counts as a failure, never a skip: a skip in a red-team report reads as a pass to
everybody who is not the person who wrote it.

### Getting started on a domain

```bash
attest new-profile mortgage --jurisdiction UK
pytest            # the generated profile passes conformance immediately
```

That is the openness claim, executable: the conformance suite runs in *your* repo,
against *your* profile, and fails if it can fail open.

## Design commitments

These are enforced in CI, not asserted here.

- **The base install pulls nothing.** No provider SDK, no database driver, no web
  framework. Asserted by a CI job that installs the wheel into a clean environment and
  fails if anything else appears.
- **Imports point downward only**, and the L0 kernel imports nothing outside the
  standard library. Checked by `import-linter`, because a rule that is not
  machine-checked is a preference.
- **Zero domain knowledge.** No medical, legal, financial or jurisdictional rules ship
  here. Domains are plugins, and the test is whether a team can build an agent for a
  domain none of us has heard of without modifying the framework.
- **Fail closed.** An error inside a guard, a verifier or an obligation is an
  unsatisfied warrant, never a pass. Several of these are unrepresentable rather than
  merely discouraged — a warrant whose check did not run cannot be constructed claiming
  it passed.
- **Uncertainty is typed.** `UNKNOWN` and `UNVERIFIABLE` are real outcomes a caller must
  handle. A payment that timed out after the bank committed it is neither success nor
  failure, and coercing it to either is a lie.

## Installation

Not on PyPI yet. Install from a **pinned commit** — a branch reference re-resolves on
every build, which is a strange property for a package whose subject is reproducible
records.

```bash
pip install "attest-control-plane @ git+https://github.com/Threx-code/attest.git@<sha>"
```

Extras go on the name, not the URL:

```bash
pip install "attest-control-plane[django,postgres] @ git+https://github.com/Threx-code/attest.git@<sha>"
```

In a requirements file or `pyproject.toml`:

```
attest-control-plane[django] @ git+https://github.com/Threx-code/attest.git@a1b2c3d
```

Get the SHA with `git ls-remote https://github.com/Threx-code/attest.git main`.

**Python 3.11+.** The base install pulls two wheels — `asn1crypto` and `cryptography`,
required rather than optional because verification a deployment has to opt into is a
control that is off by default. Everything else is an extra:

| Extra | Pulls |
|---|---|
| `django`, `postgres`, `redis`, `celery`, `fastapi` | the adapter's own dependencies |
| `anthropic`, `openai`, `bedrock`, `vertex`, `gemini`, `groq`, `azure` | one provider SDK |
| `conformance` | `pytest`, for inheriting the conformance kit into your test suite |
| `all` | every adapter and provider |

`conformance` belongs in your **dev** dependencies. The kit's checks are pytest test
methods you inherit, so importing it needs pytest — and a service that only runs governed
decisions should not be shipping a test framework.

## Documentation

Start with [`docs/README.md`](docs/README.md), which gives a reading order. The three
that matter most:

| Document | Why |
|---|---|
| [`docs/concepts/warrants.md`](docs/concepts/warrants.md) | The organising idea — read first |
| [`docs/concepts/assurance-boundaries.md`](docs/concepts/assurance-boundaries.md) | What it does not prove — read second |
| [`docs/assurance/threat-model.md`](docs/assurance/threat-model.md) | 25 attacks on a single £500,000 transfer; the acceptance gate |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security issues go through private disclosure
— see [`SECURITY.md`](SECURITY.md), not the issue tracker.

## Licence

MIT. See [`LICENSE`](LICENSE).
