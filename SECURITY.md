# Security Policy

Attest governs consequential actions — money movement, clinical decisions, regulatory
filings. A defect in this library is not a bug in a demo. Please treat it accordingly.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through GitHub's [private vulnerability
reporting](https://github.com/Threx-code/attest/security/advisories/new), or by email to
**oluwatosin.amokeodo@gmail.com**.

Please include:

- the version or commit affected;
- which invariant you believe is broken (see *Security model* below);
- a reproduction — a failing test is ideal;
- the impact you can demonstrate, and any you suspect but cannot.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement of your report | 3 business days |
| Initial assessment and severity | 10 business days |
| Fix or documented mitigation for critical issues | 30 days |
| Public advisory | after a fix ships, coordinated with you |

We will credit you in the advisory unless you ask us not to. We do not currently operate
a paid bounty.

## Supported versions

Until 1.0, only the latest minor release receives security fixes.

| Version | Supported |
|---|---|
| 0.1.x | ✅ |
| < 0.1 | ❌ |

## Security model

Attest's central structural claim is:

> **Agents may propose actions. They cannot authorize or execute consequential effects.**

A report is in scope if it breaks that claim, or any of the invariants below.

### In scope

- **Authorization binding** — redeeming a grant against an action other than the exact
  one it was issued for; mutating an action after authorization.
- **Grant integrity** — forging, replaying, or reusing a single-use grant; nonce reuse;
  using an expired or revoked grant; racing two redemptions of the same grant.
- **Policy integrity** — downgrading a policy or profile version; evaluating against a
  policy other than the one recorded in the attestation.
- **Audit integrity and completeness** — tampering with a sealed chain without detection;
  inserting, reordering, or omitting events; forging a seal signature or witness receipt.
- **Tenant isolation** — reading, writing, or inferring another tenant's evidence, memory,
  attestations, or audit events.
- **Delegation and scope** — a child agent obtaining authority its parent could not
  delegate; scope escalation through handoff, memory, or tool access.
- **Boundary failures** — direct or indirect prompt injection that causes an action to be
  proposed *and authorized*; PII or restricted evidence leaving the boundary.
- **Evidence integrity** — forging provenance, passing off unverified evidence as
  verified, or causing a `FAIL`/`UNVERIFIABLE` result to be reported as `PASS`.
- **Execution semantics** — causing an `UNKNOWN` effect to be silently recorded as
  committed or failed; duplicate execution of a single authorized effect.
- **Resource exhaustion** — unbounded agent loops, recursive delegation, or evidence sets
  that exhaust memory or budget without a bounded failure.
- **Deserialization** — code execution or state corruption from untrusted attestation,
  evidence, or memory payloads.

### The shipped HTTP surface

`attest.adapters.django` publishes routes, and a framework whose safety depends on a
setting the host may not have set is not fail-closed. What the adapter guarantees:

| Concern | Default | Why not the framework default |
|---|---|---|
| Authentication | `IsAuthenticated`, set on each class | DRF's `DEFAULT_PERMISSION_CLASSES` is `AllowAny` unless a project changed it. Inheriting it would mean mounting `urls.py` publishes an unauthenticated route that can execute governed actions. |
| Tenant scoping | applied in the queryset | Filtering after the query means the rows were already read across tenants, so a scoring or filter bug becomes a data leak rather than a wrong page. |
| Cross-tenant dispatch | refused `403`, before the engine | An authenticated caller proposing for another tenant is the confused deputy. The engine would otherwise produce a perfectly sealed attestation naming a tenant the caller was never entitled to touch. |
| Unresolvable tenant | refused `403` | There is no reading of "we cannot tell who you are" that permits acting for someone. |
| Disclosure | `DisclosureProfile.SUBJECT` | A refusal carries operator-facing `detail` and subject-facing `subject_message`. The serialiser does not know who is on the socket, so it withholds the reasoning and an operator console opts in. |
| Rate limiting | `throttle_scope = "attest"` declared | A dispatch spends model budget and can move money. The scope exists so limiting it is a settings change rather than a code change. |
| Warnings | never withheld, from any audience | This one outranks disclosure. A warning a caller cannot see is a warning that does not exist. |

Two things the adapter deliberately does **not** do, because only the host can:

- **It does not resolve identity.** `tenant_for()` returns `None` by default, which
  yields an empty queryset and a refused dispatch. An unwired deployment is inert, not
  permissive.
- **It does not build the engine.** `DispatchView.engine_for()` raises until a host
  supplies one, because the engine holds the profile, the stores and the executor — and
  a view that assembled those from settings would be a second, divergent definition of
  what the deployment is.

A report is in scope if any of those defaults can be bypassed without the host having
deliberately overridden them.

### Out of scope

- **Model correctness.** Attest does not establish that a decision is *correct*, and
  explicitly documents this — see
  [`docs/concepts/assurance-boundaries.md`](docs/concepts/assurance-boundaries.md). "The
  model produced a wrong answer" is not a vulnerability. "The framework presented an
  unverified answer as verified" is.
- Vulnerabilities in a host application's own adapter implementations.
- Vulnerabilities in optional third-party dependencies, unless Attest's use of them is
  what creates the exposure. Report those upstream; tell us too.
- Attacks requiring the attacker to already hold the signing key, or write access to the
  audit store, unless the design claims to resist that. It does not: see the trust model.

### Trust model

Attest assumes:

- the **host** is trusted to run the kernel honestly and to protect its signing key;
- the **model, its output, all retrieved evidence, and all memory are untrusted**;
- the **audit store is trusted for availability, not for integrity** — integrity comes
  from the hash chain and the seal signature, which are verifiable offline;
- **completeness of the record** is guaranteed only within the declared witness
  configuration. A host that can rewrite its own storage can truncate an unwitnessed
  chain. This is why external witnessing exists, and why its absence is recorded.

Claims stronger than these are bugs in the documentation. Please report those too.
