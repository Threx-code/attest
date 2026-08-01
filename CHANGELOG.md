# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until 1.0.0 the public API is unstable: minor versions may break it, and breaking changes
are always listed under `### Changed` with a migration note.

## [Unreleased]

First release in preparation. Nothing has shipped yet, so there is no upgrade path to
document — this section describes what 0.1.0 will contain.

### Added

- **L0 kernel.** Canonical content addressing, typed identifiers, the six-outcome
  `Verdict`, open `WarrantKind` / `EvidenceKind` / `EffectClass`, the effect lifecycle
  with its terminal `UNKNOWN` state, authorization grants bound to an exact action hash,
  hash-chained audit events with seal-time sequencing, and the execution-context
  snapshot that makes verification reproducible.
- **L1 capabilities.** Evidence verification, coverage, obligations and grant issuance,
  the execution boundary, reconciliation, chain sealing, guards, memory, judging,
  witnessing, approvals, the provider gateway, prompts, dataset lineage, and domain
  profiles with conflict-classifying composition.
- **L2 runtime.** Declarative agent specs, `Scope` enforced at every boundary,
  delegation with transitive subsetting, the `Flow` graph with static validation,
  intent routing that deflects rather than guessing, three replay modes, and two-phase
  streaming.
- **L3 assurance.** The conformance kit a domain package inherits, all ten red-team
  families, and offline-verifiable evidence bundles with a generated `VERIFY.md`.
- **L4 adapters.** Reference in-memory stores, and a SQLite store enforcing
  append-only and immutability with database triggers.
- **The `RunEngine` entry point** — one proposal in, one sealed attestation out. Warrants
  are evaluated before a grant is issued and the grant before the executor is reachable,
  so a blocked run cannot reach an effect. An upstream timeout becomes `UNKNOWN` rather
  than a failure, because the upstream may have committed and saying otherwise is a lie.
  `VerdictResolver` maps warrants and effect states onto the six outcomes in one place
  instead of leaving every host to re-derive it.
- **`AttestationCodec` and `AuditEventCodec`** — the wire format that makes a record
  outlive this package. Decoding **verifies the content hash**, so an altered payload or
  a codec that drifted from the value objects fails at read time rather than returning a
  plausible record. Scalars round-trip through the same canonical layer the hash is taken
  over, and a value that would come back as a different type is refused at write time.
- **Seven provider backends** behind the gateway — Anthropic, Claude on Vertex, Gemini
  (on Vertex or the Developer API), OpenAI (with Azure as a parameter rather than a
  second implementation), Bedrock over the
  Converse API, Groq, and a dependency-free deterministic backend for conformance runs
  and air-gapped deployments. Each loads its SDK inside a method, so the base install
  still pulls no provider SDK. A policy refusal, a content filter or an empty completion raises
  rather than being recorded as an answer; an explicit Claude catalogue withholds
  sampling parameters from models that reject them and refuses a `max_tokens` above the
  model's own ceiling before spending anything.
- **Model families resolved from the weights, never the vendor** — the input to the
  cross-family judging rule, and the reason a Groq-served Llama cannot be counted as an
  independent judge of a Bedrock-served one. An unrecognised model resolves to nothing
  and the operator must state the family, because a guess there is an independence
  claim nobody made.
- **The Django adapter** — settings bridge, models, migrations *including the
  append-only and immutability triggers for SQLite, PostgreSQL and MySQL*, port
  implementations, DRF serialisers that cannot drop the verdict or the warnings,
  tenant-scoped views with no permissive default, a read-only admin, and the
  `verify_audit_chain`, `expire_pending` and `export_bundle` commands. A migration on
  an unsupported database vendor raises rather than silently applying nothing, and
  `verify_audit_chain` recomputes event hashes from content rather than trusting the
  stored linkage.
- **A dispatch endpoint** returning the attestation rather than the answer, at a status
  derived from the verdict. Its security defaults are set on the class rather than
  inherited: authentication is required (DRF's project default is `AllowAny`), a
  proposal naming another tenant is refused before the engine, and disclosure defaults
  to the subject profile so internal reasoning is not returned to the person it is
  about. Warnings are withheld from nobody.
- **`attest new-profile`** — scaffolding whose conformance suite passes on generation.
- **The model gateway, wired to the run.** `ModelGateway` is the only thing that calls
  a provider, and a `ModelSession` scoped to one run accumulates what it spent — a run
  is not one model call, so an agent's several calls all land in one record. Residency
  is read from `TenantBinding.residency_regions` rather than taken as a constructor
  argument, closing a hole where every attestation serialised a boundary that nothing
  enforced. A `ModelCallLog` is bound to the run's context hash, so `RunEngine` treats
  it as evidence rather than as a claim and derives cost and the model ref from it
  instead of believing what it was told. Retry with backoff and jitter comes *before*
  failover, because a blip answered by a fallback would record a materially different
  decision; the circuit breaker fast-fails a degraded provider; exact caching is keyed
  on the corpus epochs so a document update invalidates the answers derived from it;
  semantic caching has no default implementation because a near-miss answer is a
  domain's decision; and `DriftCanary` compares frozen prompts against recorded
  baselines and emits a version marker so attestations either side of a silent model
  change are distinguishable. Budget enforcement stays in the obligation layer, per
  `docs/capabilities/llm-gateway.md` — the gateway measures, the obligation layer
  decides. Five audit events the kernel defined and nothing emitted now fire.
- **Adversarial-review fixes.** A `REFUSE` verdict can no longer be written over an
  effect that reached the outside world — the kernel refuses to construct one, and the
  resolver produces `INCOMPLETE` instead, because "nothing happened" and "some of it
  happened" require different human responses. An action bound to a different tenant or
  actor than the run it arrived in is refused at the grant mint and again at the
  execution boundary: the grant took its tenant *from the action*, so every downstream
  check compared the action against itself and agreed. Budget reservation ids come from
  a monotonic per-scope counter rather than a count of live reservations, so a swept
  worker's late commit cannot consume a different reservation that reused its id.
- **An executable invariant register** (`tests/test_invariants.py`) naming, for 45
  security invariants, what is claimed, where it is enforced, and which test proves it
  — checked against pytest's own collected node ids so it cannot drift.
- **A class-based design gate** (ADR 0042) failing the build on any module-level
  function in the package.
- **Machine-checked architecture.** `import-linter` contracts enforcing the L0–L4
  dependency rule and the purity of the kernel, so the layering cannot decay silently.
- **Enterprise CI.** Lint, `mypy --strict`, layer contracts, a test matrix across
  Python 3.11–3.13 on Linux/macOS/Windows, a separately-reported adversarial suite,
  `bandit`, `pip-audit`, a byte-identical reproducible-build check, a documentation
  consistency gate, a clean-environment install asserting the base package pulls only its
  two declared dependencies, and the append-only trigger DDL executed against real
  PostgreSQL and MySQL rather than only SQLite.
- **Tools.** `ToolSpec` declares what a tool is — effects, semantics, capability,
  idempotency — and `propose()` builds the `Action` from that declaration rather than
  from the caller, so a profile's authority rules dispatch on what the tool *is* instead
  of on what a call site claimed. `ToolRegistry.advertise()` filters the list by
  capability **before the model sees it** and strips the capability name from what it
  advertises. Registration is the checkpoint: a `KEYED` or `FORBIDDEN` tool with no way
  to derive an idempotency key fails at import rather than at 2am, and the schema
  validator refuses a keyword it cannot enforce instead of ignoring it.
- **Contestability** — the reason a decision went the way it did, what would change it,
  and what the subject can do about it. Required in several target domains, so it is
  computed rather than narrated: rule attribution, then boundary search over the
  deterministic part of the decision, then ranked principal factors. A model judgement is
  reported and **never inverted into a threshold**, because a model-generated explanation
  is a plausible story rather than a cause. Where no counterfactual can be computed the
  warrant fails, which is what routes the decision to a human. The subject message is
  machine-checked against the internal record: two explanations for one decision is the
  finding an ombudsman looks for.
- **Observability.** `Signals.over(attestations)` derives what only the kernel holds —
  the full six-verdict mix, warrant satisfaction by kind, refusal rate by reason, the
  unverifiable-evidence rate that rises months before anything visibly fails, and cost
  per decision. Every measurement carries the population it was computed over, because a
  ratio whose denominator collapsed reads as healthy. Six signals are separated as
  incidents rather than dashboard lines and carry run ids, and what an attestation
  *cannot* yield is listed rather than quietly omitted.
- **Evaluation.** Golden sets with structural expectations — verdict, warrant status,
  obligations, refusal reason, cost ceiling — and deliberately no way to assert exact
  answer text, because a suite that pins prose is disabled within a month. A regression
  gate that reports the diff rather than deciding, since a golden set records what the
  system used to do and changing that is often the point. Metrics report refusal rate
  and groundedness together and flag the shape where one rises without the other
  falling. Calibration flags overconfidence and not underconfidence. The framework ships
  the harness; the domain ships the cases.
- **Queued dispatch.** `RunQueue` and `RunWorkQueue`, a durable leased queue on the
  database with no broker required, and a Celery wrapper for hosts that have one. A held
  run leaves the worker rather than parking a thread until somebody clicks, and each
  attempt seals its own immutable attestation superseding the last — so a resumed run
  produces a record instead of colliding with the one it already wrote.
- **Signing and timestamping.** An Ed25519 signer so a bundle is bound to its issuer
  rather than merely internally consistent, and full RFC 3161 verification — signature,
  certificate chain, message imprint — with what is *not* checked stated explicitly on
  the assertion.
- **Operational surface.** `OperationsService` exposes the kill switch, the approval
  queue, chain verification, queue health and reconciliation over the ports, and
  authorises nothing: every adopter has roles already, and a framework shipping its own
  would be wired up beside the real one. Every mutating operation names an operator and
  states a reason.
- **Reconciliation, wired.** An `UNKNOWN` effect is a work item with a worker now:
  the sweep asks the upstream, records `effect.reconciled` — including "we asked and
  could not find out" — and supersedes the attestation rather than mutating it. The
  correction is written under its own run, because the original is sealed and the
  append-only guard is not negotiable for a payment nobody can account for.
- **Shared state for multi-process deployments.** A Redis-backed circuit breaker and
  exact cache, so N workers do not each grant a degraded provider its own failure budget,
  with degradation reported rather than silently absorbed. Table partitioning with an
  archival path for the audit chain.
- **Conformance suites for the three atomicity ports** — `IdempotencyStore`,
  `BudgetStore` and `RunWorkQueue` — each built around the concurrency check a sequential
  test cannot make, plus `Build`, valid-by-construction kernel values so an adopter
  writing their first test is not fighting six invariants to get a record the kernel
  accepts.
- **Findings no profile may soften.** `NON_DOWNGRADEABLE` floors a cross-tenant read, an
  outbound leak and an unrestored redaction token below any warrant policy — keyed on the
  finding rather than the warrant kind, so a deployment that legitimately records
  injection heuristics rather than blocking on them does not thereby switch off tenancy
  isolation.
- **The red-team corpus executes.** Eighteen adversarial proposals run against a real
  engine, with a case that declares no attack counted as a failure rather than skipped.
  `pytest -m redteam` is the command an adopter runs against their own profile.
- **Security policy** with an explicit trust model and in-scope invariants, and
  **contribution rules** documenting the non-negotiable architectural constraints.

[Unreleased]: https://github.com/Threx-code/attest/compare/main...HEAD
