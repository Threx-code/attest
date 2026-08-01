"""Refuse a security control that nothing calls.

The recurring defect class in this package was never a wrong algorithm. It was a
collaborator accepted, stored, and never invoked: an ``ApprovalStore`` the engine held
and never called, a ``BudgetStore.commit`` with no callers, a ``DisclosureProfile``
read by nothing, a ``MemoryGuard`` wired to no store. Fifteen distinct controls were
present, correct in isolation, covered by green tests, and absent from every execution
path.

**The tests are what made it invisible.** Each control was tested *directly*, so CI
proved the mechanism worked and never asked whether anything invoked it.
``DelegationChain.delegate`` had eight tests and no caller; ``ConsistencyProof.verifies``
had three, which meant the mechanism that defeats history rewriting was never run by the
system it defends.

So this checks the question the tests do not: for every method named below, is there a
call to it somewhere in ``src/`` other than its own definition? A control that fails is
either wired or deleted. There is a third option — declared as host-driven API — and it
costs a line here with a reason attached, which is the point: the decision becomes
visible rather than accidental.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import ClassVar


class Reachability:
    """Walks ``src/`` and reports controls nothing calls."""

    ROOT = Path("src/attest")

    #: Methods that enforce something. Each must be called from somewhere in src/, or
    #: appear in HOST_DRIVEN with a reason.
    CONTROLS: ClassVar[dict[str, str]] = {
        "screen": "injection screening",
        "screen_inbound": "inbound screening",
        "screen_evidence": "tenancy on evidence",
        "screen_evidence_content": "injection screening of retrieved documents",
        "screen_write": "memory write policy",
        "recallable": "tenant and TTL filter at recall",
        "restore": "PII restoration",
        "check_against": "grant binding at the effect boundary",
        "redeem": "single-use nonce",
        "is_revoked": "grant revocation",
        "claim": "cross-run idempotency",
        "commit": "budget settlement",
        "release": "budget release",
        "decisions": "recorded human approvals",
        "consume": "an approval is spendable once",
        "discharge": "obligations",
        "evaluate": "warrants",
        "verify": "evidence and chains",
        "verifies": "consistency proofs",
        "verifies_against": "inclusion proofs",
        "assert_exportable": "export refuses to overclaim",
        "assert_own_tenant": "the confused deputy",
        "reclaim_expired": "runs whose worker died",
        "expire_due": "approval and reservation expiry",
    }

    #: Declared host-driven API: a library a host calls, not something this package
    #: drives. Each needs a reason, and the reason has to survive being read aloud.
    HOST_DRIVEN: ClassVar[dict[str, str]] = {
        "permits_tool": "Scope is the delegation library; a supervisor is the host's",
        "permits_corpus": "as permits_tool",
        "permits_evidence": "as permits_tool",
        "assert_permits": "ReplayPlan is driven by the host's replay runner",
        "citable_as_evidence": "a property a host reads when citing recalled memory",
        "issue_receipt": "issued at decision time by the host, before or with the effect",
    }

    def sources(self) -> dict[Path, str]:
        return {path: path.read_text() for path in self.ROOT.rglob("*.py")}

    #: Controls that are read rather than called. A property has no ``Call`` node, so it
    #: has to be named here — the alternative was a second pass over every attribute
    #: access, which counted `store.consume` (never invoked) as a call and made the gate
    #: unable to fail.
    PROPERTIES: ClassVar[frozenset[str]] = frozenset(
        {"citable_as_evidence", "independent", "key_id", "spec"}
    )

    def calls(self, sources: dict[Path, str]) -> set[str]:
        """Every name that is genuinely **invoked**, and nothing else.

        Strictly ``ast.Call`` nodes. The previous version added a second pass over every
        ``ast.Attribute`` guarded by ``getattr(node, "parent", None)`` — and ``ast``
        nodes carry no ``parent``, so the guard was always ``None``, the condition
        always true, and every attribute *access* in the package counted as a call. The
        set was 1521 names where a strict scan finds 766.

        Nothing depended on it: under a strict scan every listed control is genuinely
        invoked, so the gate was passing on merit. But a change that demoted a call to a
        bare reference — ``handler = store.consume`` without invoking it, a ``getattr``
        guard, a type annotation — would have kept it green. The gate that enforces this
        codebase's most important structural lesson must not be able to stop working
        quietly.
        """
        found: set[str] = set()
        for text in sources.values():
            for node in ast.walk(ast.parse(text)):
                if not isinstance(node, ast.Call):
                    continue
                target = node.func
                if isinstance(target, ast.Attribute):
                    found.add(target.attr)
                elif isinstance(target, ast.Name):
                    found.add(target.id)
        return found

    def reads(self, sources: dict[Path, str]) -> set[str]:
        """Attribute *accesses*, for the controls that are properties.

        Kept separate from :meth:`calls` and consulted only for names in
        :attr:`PROPERTIES`, so a property cannot launder a method into looking invoked.
        """
        found: set[str] = set()
        for text in sources.values():
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Attribute):
                    found.add(node.attr)
        return found

    def port_methods(self) -> dict[str, str]:
        """Every method on every port Protocol. **Derived, not hand-listed.**

        The hand-maintained list is why ATT-56 happened: ``SealRegistry.close`` was
        added, had no caller, and the gate said nothing because nobody had thought to
        add it. A control the framework declares a *port* for is a control by
        construction, so the list comes from the ports themselves and a new one is
        covered the moment it is declared.
        """
        found: dict[str, str] = {}
        tree = ast.parse((self.ROOT / "kernel" / "ports.py").read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(isinstance(base, ast.Name) and base.id == "Protocol" for base in node.bases):
                continue
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and not item.name.startswith("_"):
                    found[item.name] = f"{node.name}.{item.name}"
        return found

    def report(self) -> list[str]:
        sources = self.sources()
        called = self.calls(sources)
        read = self.reads(sources)
        problems: list[str] = []
        controls = {**self.port_methods(), **self.CONTROLS}
        for name, what in controls.items():
            if name in self.HOST_DRIVEN:
                problems.append(f"{name}: listed as both a control and host-driven; pick one")
                continue
            reached = called if name not in self.PROPERTIES else called | read
            if name not in reached:
                problems.append(
                    f"{name} enforces {what} and nothing in src/ calls it. Wire it, "
                    f"delete it, or declare it host-driven with a reason."
                )
        return problems


def main() -> int:
    problems = Reachability().report()
    if problems:
        sys.stdout.write("Unreachable security controls:\n")
        for problem in problems:
            sys.stdout.write(f"  {problem}\n")
        return 1
    sys.stdout.write("Reachability check passed.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
