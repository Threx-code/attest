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
        "at": "LeafSource is implemented over the host's storage; the package never indexes it",
        "prompt": "AgentSpec.prompt is rendered by the host's own template layer",
        "completion_floor": (
            "the engine builds no CompletionRequest; the host holds both the AgentSpec "
            "and the request, and this is the bridge it calls"
        ),
        "model_tier": (
            "read only by completion_floor, which is host-driven for the same reason. "
            "Named on its own line rather than inheriting that, because a field whose "
            "only reader is host-driven API is a field the package does nothing with"
        ),
    }

    def __init__(self) -> None:
        self._properties: set[str] = set(self.PROPERTIES)
        """Names that can only be satisfied by a read. Seeded from the hand-list, then
        grown by :meth:`port_methods` as it meets ``@property`` declarations."""

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

    def reads(self, sources: dict[Path, str], *, outside_host_driven: bool = False) -> set[str]:
        """Attribute *accesses*, for the controls that are properties.

        Kept separate from :meth:`calls` and consulted only for names in
        :attr:`PROPERTIES`, so a property cannot launder a method into looking invoked.

        ``outside_host_driven`` skips the bodies of methods named in
        :attr:`HOST_DRIVEN`, and the field check uses it. Without it the check launders
        in the same way: adding a one-line accessor that nothing calls would make a dead
        field look live. A field reachable only through host-driven API is host-driven
        too, and has to say so on its own line rather than inherit it.
        """
        found: set[str] = set()
        for text in sources.values():
            tree = ast.parse(text)
            skip: set[int] = set()
            if outside_host_driven:
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name in self.HOST_DRIVEN:
                        skip.update(id(inner) for inner in ast.walk(node))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and id(node) not in skip:
                    found.add(node.attr)
        return found

    def indirect(self, sources: dict[Path, str]) -> set[str]:
        """Names reached through ``getattr`` or ``hasattr``, where the name is a string.

        Neither scan above can see these: it is not an attribute node, and the call node
        names ``getattr`` rather than the thing being fetched. `DomainProfile.
        policy_dimensions` is consulted exactly this way, so without this the gate
        reported a control that is genuinely wired - and a gate that cries wolf is a
        gate somebody starts suppressing.
        """
        found: set[str] = set()
        for text in sources.values():
            for node in ast.walk(ast.parse(text)):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in {"getattr", "hasattr"}
                    and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and isinstance(node.args[1].value, str)
                ):
                    found.add(node.args[1].value)
        return found

    def port_methods(self, sources: dict[Path, str]) -> dict[str, str]:
        """Every method on every port Protocol. **Derived, not hand-listed.**

        The hand-maintained list is why ATT-56 happened: ``SealRegistry.close`` was
        added, had no caller, and the gate said nothing because nobody had thought to
        add it. A control the framework declares a *port* for is a control by
        construction, so the list comes from the ports themselves and a new one is
        covered the moment it is declared.

        **Every file, not just ``kernel/ports.py``.** This scanned that one file, and
        ``AutonomyStore`` — the kill switch — was declared in ``runtime/operations.py``,
        so its methods were never in the control set. The result is the exact defect
        this script exists to catch: ``set_mode`` was written by the operations console,
        recorded on the append-only trail, and read by nothing on any execution path,
        while this gate passed. ``docs/kernel/ports.md`` even listed the port under a
        name that appeared nowhere in the code.

        A Protocol is the declaration "this is a seam somebody plugs into", and where
        the file happens to sit is not part of that claim.
        """
        found: dict[str, str] = {}
        for path, text in sorted(sources.items()):
            for node in ast.walk(ast.parse(text, filename=str(path))):
                if not isinstance(node, ast.ClassDef):
                    continue
                if not any(
                    isinstance(base, ast.Name) and base.id == "Protocol" for base in node.bases
                ):
                    continue
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and not item.name.startswith("_"):
                        if self._is_property(item):
                            # Derived rather than added to PROPERTIES by hand. A property
                            # has no Call node, so it can only ever be satisfied by a
                            # read - and a hand-list of them is the same artefact the
                            # control list stopped being.
                            self._properties.add(item.name)
                        found.setdefault(item.name, f"{node.name}.{item.name}")
        return found

    @staticmethod
    def _is_property(item: ast.FunctionDef) -> bool:
        return any(
            (isinstance(d, ast.Name) and d.id == "property")
            or (isinstance(d, ast.Attribute) and d.attr == "property")
            for d in item.decorator_list
        )

    #: Dataclasses whose fields cross a layer boundary, and are therefore contracts. A
    #: field declared here and read nowhere is the same defect as an uncalled control,
    #: and it is invisible to the call scan below: `warrant_overrides` on `AgentSpec`
    #: was never an `ast.Call`, so an agent declaring a STRICTER policy than its
    #: deployment silently got the looser one and this gate had nothing to say.
    CONTRACT_TYPES: ClassVar[frozenset[str]] = frozenset({"AgentSpec", "RunRequest"})

    def contract_fields(self, sources: dict[Path, str]) -> dict[str, str]:
        """Every public field on a type in :attr:`CONTRACT_TYPES`.

        Fields, not methods, because the failure mode is different in shape and
        identical in consequence: a caller fills the field in, the value is carried,
        serialised, hashed, and never consulted. From the caller's side that is
        indistinguishable from a setting that had no effect because it was already the
        default.
        """
        found: dict[str, str] = {}
        for path, text in sorted(sources.items()):
            for node in ast.walk(ast.parse(text, filename=str(path))):
                if not isinstance(node, ast.ClassDef) or node.name not in self.CONTRACT_TYPES:
                    continue
                for item in node.body:
                    if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                        name = item.target.id
                        if not name.startswith("_"):
                            found.setdefault(name, f"{node.name}.{name}")
        return found

    def report(self) -> list[str]:
        sources = self.sources()
        called = self.calls(sources) | self.indirect(sources)
        read = self.reads(sources)
        problems: list[str] = []
        ports = self.port_methods(sources)
        for name, what in {**ports, **self.CONTROLS}.items():
            if name in self.HOST_DRIVEN:
                # A hand-listed control that is also declared host-driven is a
                # contradiction somebody should resolve. A *derived* port method that is
                # declared host-driven is the escape hatch working as intended - the
                # whole point of HOST_DRIVEN is that it costs a line with a reason.
                if name in self.CONTROLS:
                    problems.append(f"{name}: listed as both a control and host-driven; pick one")
                continue
            reached = called if name not in self._properties else called | read
            if name not in reached:
                problems.append(
                    f"{name} enforces {what} and nothing in src/ calls it. Wire it, "
                    f"delete it, or declare it host-driven with a reason."
                )
        driven = self.reads(sources, outside_host_driven=True)
        for name, what in self.contract_fields(sources).items():
            if name in self.HOST_DRIVEN or name in called or name in driven:
                continue
            problems.append(
                f"{what} is declared, and every read of it is inside host-driven API. A "
                f"caller can set it and the package will do nothing with it. Wire it, "
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
