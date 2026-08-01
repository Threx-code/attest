#!/usr/bin/env python3
"""Fail the build when the documentation contradicts itself.

These checks exist because each corresponding contradiction was actually found in
the doc set, not because they are hypothetically possible.

1. A document claiming a decision is "open" while docs/decisions/README.md says
   `Open: None`. Three documents did exactly this, pointing at decisions that had
   already been settled by ADR 0011 and ADR 0012.

2. A withdrawn replay-mode name (STRICT / PINNED / CURRENT) reappearing. Four names
   for three modes, with STRICT ambiguous between two of them. See ADR 0037.

3. A four-member Verdict enum. UNKNOWN and INCOMPLETE are reachable outcomes and
   must be members, or exhaustive matching does not do what it claims. See ADR 0033.

4. **A capability document with no module behind it.** Four of these shipped: `tools`,
   `contestability`, `observability` and `eval`. Each read exactly like a capability
   the package had — one of them describing a legal obligation, one describing the
   first layer of the defence-in-depth diagram in the threat model — and none of them
   existed. They were found by sweeping the doc set by hand, twice, months apart, which
   is the point of this check: a sweep somebody remembers to run is an artefact, and a
   gate is a control. Leaving this one to memory would be the joke writing itself.

Run: python scripts/check_docs_consistency.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

DOCS = Path(__file__).resolve().parent.parent / "docs"

# 1 ── "open decision" vs the ADR index -------------------------------------------------
OPEN_CLAIM = re.compile(
    r"(open decision|not yet settled|decision is open|undecided)",
    re.IGNORECASE,
)

# 2 ── withdrawn replay vocabulary ------------------------------------------------------
# Upper-case and word-boundary matched, so prose like "stricter wins" is not a hit.
# Covers "STRICT replay", "STRICT mode", and a bare "in STRICT" — the first pass of this
# check only matched "<NAME> replay" and missed two live instances in redteam.md.
# Must be followed by "replay" or "mode": the withdrawn names were only ever used that
# way. A bare CURRENT is legitimate ("framework CURRENT", "policy=CURRENT") and matching
# it produced false positives on the first attempt.
WITHDRAWN_REPLAY_NAMES = re.compile(r"\b(STRICT|PINNED|CURRENT)\s+(replay|mode)\b")

# 3 ── the Verdict enum must carry all six reachable outcomes ---------------------------
REQUIRED_VERDICTS = (
    "ALLOW",
    "ALLOW_WITH_WARNINGS",
    "HOLD_FOR_APPROVAL",
    "REFUSE",
    "UNKNOWN",
    "INCOMPLETE",
)


# 4 ── every capability document has a module -------------------------------------------
SRC = Path(__file__).resolve().parent.parent / "src" / "attest"

#: Documents whose subject is genuinely not a module, each with the reason. **This is
#: the list that must be argued for.** Adding a name here to make the build pass is the
#: failure mode, so each entry says what the document *is* if it is not a capability.
DOC_ONLY: dict[str, str] = {
    # Cross-cutting properties, enforced across many modules rather than by one.
    "kernel/determinism.md": "a property every module upholds; enforced by the Clock and "
    "IdGenerator ports and by the ban on ambient randomness",
    "kernel/tenancy.md": "a boundary enforced in TenantBinding, TenancyGuard and "
    "NON_DOWNGRADEABLE, not a module of its own",
    "kernel/versioning.md": "a policy over fields that already exist on ProfileRef and "
    "ExecutionContext",
    "kernel/performance.md": "budgets and targets; the mechanism is Budget and CostRecord",
    "kernel/storage.md": "the shape a host's storage must have; the contracts are the ports",
    # Naming: the document is named for the concept, the module for the mechanism.
    "kernel/execution-context.md": "implemented as kernel/context.py",
    "capabilities/llm-gateway.md": "implemented as capabilities/gateway.py",
    "runtime/chains.md": "implemented as runtime/composition.py (Flow)",
    "runtime/orchestration.md": "implemented as runtime/composition.py and runtime/router.py",
    # Method and threat documents rather than capability documents.
    "assurance/threat-model.md": "a threat model; its enforcement points are named per attack",
    "assurance/testing.md": "how to test; the harness is assurance/conformance.py",
}


def _capability_documents() -> list[tuple[str, Path]]:
    """Every document that should name a module, with the module it implies."""
    found: list[tuple[str, Path]] = []
    for area in ("capabilities", "runtime", "kernel", "assurance"):
        for path in sorted((DOCS / area).glob("*.md")):
            if path.stem in {"README", "index"}:
                continue
            found.append((f"{area}/{path.name}", SRC / area / f"{path.stem}.py"))
    return found


def _index_declares_no_open_decisions(index: Path) -> bool:
    if not index.is_file():
        return False
    return bool(
        re.search(r"^##\s*Open\s*$\s+^None\.", index.read_text(encoding="utf-8"), re.MULTILINE)
    )


def main() -> int:
    failures: list[str] = []
    index = DOCS / "decisions" / "README.md"
    no_open = _index_declares_no_open_decisions(index)

    for path in sorted(DOCS.rglob("*.md")):
        rel = path.relative_to(DOCS.parent)
        lines = path.read_text(encoding="utf-8").splitlines()

        for n, line in enumerate(lines, 1):
            if no_open and path != index and OPEN_CLAIM.search(line):
                failures.append(
                    f"{rel}:{n}: claims a decision is open, but "
                    f"docs/decisions/README.md says 'Open: None'.\n"
                    f"    {line.strip()}"
                )
            if (hit := WITHDRAWN_REPLAY_NAMES.search(line)) and "withdrawn" not in line:
                failures.append(
                    f"{rel}:{n}: uses the withdrawn replay-mode name "
                    f"'{hit.group(0)}'. Use REPLAY_HISTORICAL / REPLAY_VERIFY / "
                    f"REPLAY_BEHAVIOURAL (ADR 0037).\n    {line.strip()}"
                )

    verdicts = DOCS / "concepts" / "verdicts.md"
    if verdicts.is_file():
        text = verdicts.read_text(encoding="utf-8")
        missing = [v for v in REQUIRED_VERDICTS if not re.search(rf"\b{v}\b", text)]
        if missing:
            failures.append(
                f"docs/concepts/verdicts.md: Verdict is missing reachable "
                f"outcome(s): {', '.join(missing)}. All six must be members or "
                f"exhaustive matching is not exhaustive (ADR 0033)."
            )

    for name, module in _capability_documents():
        if module.is_file() or name in DOC_ONLY:
            continue
        failures.append(
            f"docs/{name}: describes a capability and there is no "
            f"{module.relative_to(module.parent.parent.parent.parent)}. Either build it, "
            f"or add it to DOC_ONLY in this script with the reason it is not a module — "
            f"and the reason has to be real. Four documents shipped without an "
            f"implementation and each one read exactly like a capability the package had."
        )

    stale = sorted(set(DOC_ONLY) - {name for name, _ in _capability_documents()})
    if stale:
        failures.append(
            f"DOC_ONLY names documents that no longer exist: {stale}. An exemption for a "
            f"deleted document is an exemption waiting to cover a new one silently."
        )

    if failures:
        print("Documentation consistency check FAILED:\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print(f"\n{len(failures)} problem(s).", file=sys.stderr)
        return 1

    print("Documentation consistency check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
