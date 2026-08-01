# Contributing to Attest

Thank you for considering a contribution. Attest is infrastructure for decisions that get
audited, contested, and litigated. The bar for changes is correspondingly high, and this
document exists so that bar is explicit rather than discovered in review.

## Getting set up

```bash
git clone https://github.com/Threx-code/attest.git
cd attest
python3 -m venv .venv && source .venv/bin/activate
pip install -e . --group dev
```

Run the full local gate before opening a pull request:

```bash
make check
```

That runs, in order: format check, lint, type check, layer contracts, the full test
suite with coverage, and a build.

## The rules that are not negotiable

These are enforced in CI. They are listed here so you know *why*, not just *that*.

### 1. Imports point downward

```
adapters -> assurance -> runtime -> capabilities -> kernel
```

`attest.kernel` imports nothing outside the standard library. `attest.capabilities` never
imports `attest.runtime`. Adapters are imported by hosts, never by the core.

This is checked by `import-linter` (`lint-imports`), not by review. See
[`docs/01-layering.md`](docs/01-layering.md) for why: the discipline existed at the start
of every surveyed codebase and decayed in all of them. A rule that is not machine-checked
is a preference.

### 2. The framework ships no domain knowledge

No medical, legal, financial, or jurisdictional rules. Not in the kernel, not in
capabilities, not "just as a default". If your change requires the framework to know what
a protected class is, or how long a clinical guideline stays current, the design is wrong —
that belongs in a `DomainProfile`.

The test: *can a team build an agent for a domain none of us has heard of, without
modifying the framework?* If your change makes the answer "no", it will be rejected
regardless of how useful it is.

### 3. No silent anything

No silent fallback, no silent coercion, no swallowed exception, no default that turns
"I could not check this" into "this checked out". Where certainty cannot be established,
the type system must carry the uncertainty — `UNVERIFIABLE` is a real outcome, not a
technicality.

If you find yourself writing `except Exception: pass`, or returning a plausible default on
a failed verification, stop. That is the exact failure mode this project exists to prevent.

### 4. Security invariants are structural

"The caller is expected to check X" is not a security boundary. If an invariant matters,
it must be impossible to bypass through the public API — not merely documented as
required.

### 5. Behaviour lives on classes

No module-level functions in `src/attest`. Behaviour belongs to one of three shapes:

| Shape | For | Example |
|---|---|---|
| **Engine** | holds collaborators and configuration | `EvidenceEngine`, `AuthorityEngine`, `ChainSealer` |
| **Namespace** | the vocabulary the framework ships, where the type stays open | `WarrantKinds`, `EvidenceKinds`, `EffectClasses` |
| **Method** | behaviour belonging to one value object | `Action.action_hash()`, `EffectSemantics.may_retry_on_timeout()` |

A free function taking six arguments is an object that has not been written yet: it
cannot be injected, swapped in a test, or replaced by a domain. Module-level private
helpers are behaviour that escaped its class — make them private methods.

This decayed once already, which is why it is checked rather than preferred:
`python scripts/check_class_design.py`, wired into `make lint` and CI. See ADR 0042.

### 6. Every bug fix ships with a regression test

Permanently. Named after the failure, not the fix.

## Tests

Tests are marked, and the markers are meaningful:

| Marker | For |
|---|---|
| `unit` | isolated component behaviour |
| `integration` | interaction between components |
| `contract` | a port implementation satisfying its contract |
| `property` | invariants over generated input (hypothesis) |
| `concurrency` | races, simultaneous redemption, duplicate submission |
| `failure_injection` | crashing at a specific point in a lifecycle |
| `security` | adversarial: forgery, replay, escalation, injection, exhaustion |

```bash
pytest -m unit                       # fast loop
pytest -m security                   # the suite that must never be red
pytest -m "concurrency"              # not parallelised; they own their scheduling
```

New public behaviour needs unit *and* contract tests. New security-relevant behaviour
needs an adversarial test that fails before your change and passes after.

## Commits and pull requests

- One logical change per pull request.
- Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`,
  `build:`, `ci:`, `perf:`, `chore:`). A `!` or a `BREAKING CHANGE:` footer marks a
  breaking change.
- Update [`CHANGELOG.md`](CHANGELOG.md) under `## Unreleased` for anything user-visible.
- If you change behaviour that the documentation describes, change the documentation in
  the same pull request. Documentation that overstates what the implementation delivers is
  treated as a defect — see [`SECURITY.md`](SECURITY.md).

## Architectural changes

For anything that changes a boundary, a port signature, a warrant's semantics, or the
security model, open an issue first and expect to write an ADR in
[`docs/decisions/`](docs/decisions/). Record what was chosen, what was rejected, and what
the decision costs. "What it costs" is the part that matters in two years.

## Reporting security issues

Not here. See [`SECURITY.md`](SECURITY.md).

## Licence

By contributing you agree that your contributions are licensed under the MIT Licence, as
per [`LICENSE`](LICENSE).
